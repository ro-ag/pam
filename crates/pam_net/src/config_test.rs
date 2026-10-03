use crate::config::{ConfigDoc, EscapeError, escape};

/// What curl's config parser makes of the text between the quotes: the
/// inverse of `escape`, as `unslashquote` in curl's `tool_parsecfg.c`
/// reads it. The round trip is the proof that a value arrives unchanged.
fn curl_unquote(escaped: &str) -> String {
    let mut out = String::new();
    let mut chars = escaped.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('t') => out.push('\t'),
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('v') => out.push('\u{b}'),
                Some(other) => out.push(other),
                None => break,
            }
        } else if c == '"' {
            // An unescaped quote ends the value: anything after it would
            // be a second option.
            break;
        } else {
            out.push(c);
        }
    }
    out
}

#[test]
fn hostile_values_round_trip_through_curls_grammar() {
    let values = [
        "plain",
        "",
        "quote\"inside",
        "ends with quote\"",
        "\"starts with quote",
        "back\\slash",
        "trailing backslash\\",
        "\\\"both\\\"",
        "line\nbreak",
        "cr\rlf\n",
        "tab\there",
        "\\n is two characters",
        "\\\\n",
        "url = \"http://evil.invalid/\"\nheader = \"X: y\"",
        "@/etc/passwd",
        "-K /tmp/evil",
        "unicode ✓ ünïcödé 日本",
        "{glob,pattern}[1-3]",
        "%{stderr}%{http_code}",
        "C:\\Users\\pam\\model \"part\".bin",
        "a\" \\\" \\\\\" \"\" b",
    ];
    for value in values {
        let escaped = escape(value).unwrap_or_else(|e| panic!("{value:?}: {e}"));
        assert_eq!(curl_unquote(&escaped), value, "{value:?} -> {escaped:?}");
        // One option per line: no raw line break survives.
        assert!(
            !escaped.contains('\n') && !escaped.contains('\r'),
            "{escaped:?}"
        );
        // No unescaped quote: the value cannot end early.
        let mut previous_backslashes = 0;
        for c in escaped.chars() {
            if c == '"' {
                assert_eq!(previous_backslashes % 2, 1, "{escaped:?} has a bare quote");
            }
            previous_backslashes = if c == '\\' {
                previous_backslashes + 1
            } else {
                0
            };
        }
    }
}

#[test]
fn values_curl_cannot_carry_are_refused_not_passed_through() {
    let refused = [
        "nul\0byte",
        "escape\u{1b}[0m",
        "vertical\u{b}tab",
        "form\u{c}feed",
        "bell\u{7}",
        "del\u{7f}",
        "c1\u{85}next-line",
        "\u{0}",
    ];
    for value in refused {
        assert_eq!(
            escape(value),
            Err(EscapeError::ControlCharacter),
            "{value:?}"
        );
    }
    assert_eq!(
        EscapeError::ControlCharacter.to_string(),
        "the value holds a control character that curl's config cannot carry"
    );
}

#[test]
fn a_document_is_one_option_per_line() {
    let mut doc = ConfigDoc::default();
    doc.flag("silent");
    doc.number("max-time", 30);
    doc.string("url", "https://example.com/a?b=\"c\"").unwrap();
    assert_eq!(
        doc.string("header", "X: bad\u{0}"),
        Err(EscapeError::ControlCharacter)
    );
    assert_eq!(
        doc.finish(),
        "silent\nmax-time = 30\nurl = \"https://example.com/a?b=\\\"c\\\"\"\n"
    );
}
