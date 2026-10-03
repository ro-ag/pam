//! The document curl reads from standard input.
//!
//! curl is always started as `curl -q --config -`. Everything that varies —
//! the URL, headers, the body, file paths, the proxy and its password —
//! is a line of this document, so nothing chosen by a human, an agent or a
//! remote service is ever an argument, and nothing secret is visible to
//! `ps`.
//!
//! The grammar is curl's config-file grammar, used in its strictest form:
//!
//! * one option per line: `name = "value"`, `name = 123`, or a bare `name`
//!   for a switch;
//! * option names are compile-time constants of this crate, never input;
//! * every string value is double-quoted and passes through [`escape`], the
//!   only function that writes a value. Inside quotes curl reads `\\` as a
//!   backslash, `\"` as a quote and `\t`, `\n`, `\r` as the control
//!   characters; nothing else is special, and an unescaped quote ends the
//!   value;
//! * a value holding any other control character cannot be represented and
//!   is refused. It is never passed through and never silently dropped.

use std::fmt::Write as _;

/// The most a rendered config may weigh. A connector body is capped at
/// 16 KiB by its own validation; this bounds everything else.
pub(crate) const MAX_CONFIG_BYTES: usize = 1024 * 1024;

/// A value that cannot be written into curl's config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscapeError {
    /// The value holds a control character other than tab, line feed or
    /// carriage return: NUL would end curl's line early, and the rest have
    /// no escape in curl's grammar.
    ControlCharacter,
}

impl std::fmt::Display for EscapeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("the value holds a control character that curl's config cannot carry")
    }
}

impl std::error::Error for EscapeError {}

/// Escapes a value for a double-quoted curl config field.
///
/// The result is the text between the quotes. Backslash and quote are
/// escaped so the value cannot end early or start a new option; tab, line
/// feed and carriage return become curl's `\t`, `\n`, `\r`, which curl turns
/// back into the same bytes, so the value arrives unchanged and the document
/// stays one line per option. Any other control character (NUL, escape,
/// vertical tab, DEL, the C1 range, …) is refused.
///
/// Callers that must not carry a line break at all — a header, a URL, a
/// credential — refuse it before calling this; `escape` guarantees the
/// document's shape, not what a line break would mean to the receiver.
pub fn escape(raw: &str) -> Result<String, EscapeError> {
    let mut escaped = String::with_capacity(raw.len() + 8);
    for character in raw.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\t' => escaped.push_str("\\t"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            other if other.is_control() => return Err(EscapeError::ControlCharacter),
            other => escaped.push(other),
        }
    }
    Ok(escaped)
}

/// A config document under construction.
#[derive(Default)]
pub(crate) struct ConfigDoc {
    text: String,
}

impl ConfigDoc {
    /// A switch: the option name alone.
    pub(crate) fn flag(&mut self, name: &'static str) {
        self.text.push_str(name);
        self.text.push('\n');
    }

    /// A numeric option.
    pub(crate) fn number(&mut self, name: &'static str, value: u64) {
        writeln!(self.text, "{name} = {value}").expect("writing into a String cannot fail");
    }

    /// A string option; the value goes through [`escape`].
    pub(crate) fn string(&mut self, name: &'static str, value: &str) -> Result<(), EscapeError> {
        let escaped = escape(value)?;
        writeln!(self.text, "{name} = \"{escaped}\"").expect("writing into a String cannot fail");
        Ok(())
    }

    /// The finished document.
    pub(crate) fn finish(self) -> String {
        self.text
    }
}
