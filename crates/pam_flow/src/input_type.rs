//! Typed flow inputs: what a caller-supplied value must look like before it
//! is substituted into a command line, an environment value or a connector
//! argument.
//!
//! An input declares an optional `type:`. `string` (the default) keeps
//! today's behaviour — any text, with only the argument-option guard in
//! [`crate::vars::substitute_argv`] standing between a value and an option.
//! The other types refuse a malformed value up front, naming the input, the
//! type and the rule that was broken, and never echoing the value (it may be
//! hostile or secret-shaped):
//!
//! - `int`: decimal digits, no sign, no leading zero, at most [`MAX_INT`].
//! - `sha`: exactly 40 or 64 lowercase hexadecimal digits, not all zero.
//! - `ref`: a git ref name under `git check-ref-format` rules, implemented
//!   here rather than by running git.
//! - `path`: a relative, normalized path with no `..`, no absolute form and
//!   no drive or stream syntax. It is never checked against the filesystem;
//!   the step that uses it runs inside the repository root.
//! - `enum`: one of the `values:` the input lists.
//!
//! Validation ([`crate::parse`]) checks a default that carries no `${…}`
//! against its type; the daemon calls [`crate::Input::check`] on every
//! finished value (supplied or defaulted) before it enters [`crate::Vars`].

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::schema::Input;

/// Largest `int` input: `2^53 - 1`, the largest integer every JSON consumer
/// reads exactly.
pub const MAX_INT: u64 = 9_007_199_254_740_991;
/// Longest `ref` input, in bytes.
pub const MAX_REF_BYTES: usize = 255;
/// Longest `path` input, in bytes.
pub const MAX_PATH_BYTES: usize = 1024;
/// Most values an `enum` input may list.
pub const MAX_ENUM_VALUES: usize = 64;
/// Longest single `enum` value, in bytes.
pub const MAX_ENUM_VALUE_BYTES: usize = 128;

/// What an input's value must look like.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputType {
    /// Any text; the default.
    #[default]
    String,
    /// A non-negative decimal integer.
    Int,
    /// A full 40- or 64-digit lowercase hexadecimal object id.
    Sha,
    /// A git ref name.
    Ref,
    /// A relative, normalized path.
    Path,
    /// One of the input's `values`.
    Enum,
}

impl InputType {
    /// The name as YAML spells it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Int => "int",
            Self::Sha => "sha",
            Self::Ref => "ref",
            Self::Path => "path",
            Self::Enum => "enum",
        }
    }

    /// Whether this is the default type (omitted from rendered YAML).
    #[must_use]
    pub fn is_string(&self) -> bool {
        *self == Self::String
    }
}

/// A supplied or defaulted value broke its input's type. The message names
/// the input, the type and the rule; it never repeats the value.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("input `{input}` must be {expected}: {rule}")]
pub struct InputError {
    /// The input's name.
    pub input: String,
    /// The type it declares, as a phrase (`a decimal integer`).
    pub expected: &'static str,
    /// The rule the value broke.
    pub rule: String,
}

impl Input {
    /// Checks one finished value (after any `${repo.*}` default is filled
    /// in) against this input's declared type.
    ///
    /// # Errors
    ///
    /// [`InputError`] naming the input, its type and the rule broken. A
    /// `string` input never fails.
    pub fn check(&self, name: &str, value: &str) -> Result<(), InputError> {
        let (expected, outcome) = match self.kind {
            InputType::String => return Ok(()),
            InputType::Int => ("a decimal integer", check_int(value)),
            InputType::Sha => ("a full lowercase hexadecimal object id", check_sha(value)),
            InputType::Ref => ("a git ref name", check_ref(value)),
            InputType::Path => ("a relative path", check_path(value)),
            InputType::Enum => ("one of the listed values", check_enum(value, &self.values)),
        };
        outcome.map_err(|rule| InputError {
            input: name.to_owned(),
            expected,
            rule,
        })
    }
}

/// Refuses the declaration itself: `values` belong to `enum` and only to it.
pub(crate) fn check_declaration(kind: InputType, values: &[String]) -> Result<(), String> {
    if kind != InputType::Enum {
        return if values.is_empty() {
            Ok(())
        } else {
            Err("`values` belongs to an input of `type: enum`".to_owned())
        };
    }
    if values.is_empty() {
        return Err("an `enum` input needs a non-empty `values` list".to_owned());
    }
    if values.len() > MAX_ENUM_VALUES {
        return Err(format!(
            "the input lists {} values; the limit is {MAX_ENUM_VALUES}",
            values.len()
        ));
    }
    for (position, value) in values.iter().enumerate() {
        if value.is_empty()
            || value.len() > MAX_ENUM_VALUE_BYTES
            || value.chars().any(char::is_control)
            || value.trim() != value
        {
            return Err(format!(
                "values[{position}] must be 1 to {MAX_ENUM_VALUE_BYTES} bytes, with no control \
                 characters and no surrounding whitespace"
            ));
        }
        if values[..position].contains(value) {
            return Err(format!("values[{position}] repeats an earlier value"));
        }
    }
    Ok(())
}

fn check_enum(value: &str, values: &[String]) -> Result<(), String> {
    if values.iter().any(|allowed| allowed == value) {
        return Ok(());
    }
    Err(format!("not one of {}", values.join(", ")))
}

fn check_int(value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err("the value is empty".to_owned());
    }
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("only the digits 0-9 are allowed (no sign, spaces or separators)".to_owned());
    }
    if value.len() > 1 && value.starts_with('0') {
        return Err("no leading zeros".to_owned());
    }
    match value.parse::<u64>() {
        Ok(number) if number <= MAX_INT => Ok(()),
        _ => Err(format!("the value is above the limit {MAX_INT}")),
    }
}

fn check_sha(value: &str) -> Result<(), String> {
    if !matches!(value.len(), 40 | 64) {
        return Err("it must be exactly 40 or 64 digits long".to_owned());
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("only lowercase hexadecimal digits (0-9, a-f) are allowed".to_owned());
    }
    if value.bytes().all(|byte| byte == b'0') {
        return Err("the all-zero id names no object".to_owned());
    }
    Ok(())
}

/// Characters `git check-ref-format` never allows anywhere in a ref.
const REF_FORBIDDEN: &[char] = &[' ', '~', '^', ':', '?', '*', '[', '\\'];

/// `git check-ref-format` semantics (a one-level name such as `main` or
/// `HEAD` is fine), plus a refusal of a leading `-` so a ref can never read
/// as an option.
fn check_ref(value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err("the value is empty".to_owned());
    }
    if value.len() > MAX_REF_BYTES {
        return Err(format!("longer than {MAX_REF_BYTES} bytes"));
    }
    if value.chars().any(char::is_control) {
        return Err("no control characters (including NUL)".to_owned());
    }
    if value.starts_with('-') {
        return Err("it must not start with `-`; it would read as an option".to_owned());
    }
    if let Some(bad) = value.chars().find(|c| REF_FORBIDDEN.contains(c)) {
        return Err(format!("`{bad}` is not allowed in a ref name"));
    }
    if value == "@" {
        return Err("`@` alone is not a ref name".to_owned());
    }
    if value.contains("@{") {
        return Err("`@{` is revision syntax, not a ref name".to_owned());
    }
    if value.contains("..") {
        return Err("`..` is not allowed".to_owned());
    }
    if value.ends_with('.') {
        return Err("it must not end with `.`".to_owned());
    }
    if value.starts_with('/') || value.ends_with('/') || value.contains("//") {
        return Err("no leading, trailing or doubled `/`".to_owned());
    }
    for component in value.split('/') {
        if component.starts_with('.') {
            return Err("no path component may start with `.`".to_owned());
        }
        let bytes = component.as_bytes();
        if bytes.len() >= 5 && bytes[bytes.len() - 5..].eq_ignore_ascii_case(b".lock") {
            return Err("no path component may end with `.lock`".to_owned());
        }
    }
    Ok(())
}

/// Relative and normalized: nothing to resolve, nothing that climbs out.
fn check_path(value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err("the value is empty".to_owned());
    }
    if value.len() > MAX_PATH_BYTES {
        return Err(format!("longer than {MAX_PATH_BYTES} bytes"));
    }
    if value.chars().any(char::is_control) {
        return Err("no control characters (including NUL)".to_owned());
    }
    if value.starts_with('/') || value.starts_with('\\') {
        return Err("it must be relative to the repository, not absolute".to_owned());
    }
    if value.contains(['\\', ':']) {
        return Err(
            "write the path with `/`; `\\` and `:` (drive letters, streams) are not allowed"
                .to_owned(),
        );
    }
    if value.starts_with('-') {
        return Err("it must not start with `-`; it would read as an option".to_owned());
    }
    for component in value.split('/') {
        match component {
            "" => return Err("no empty component (`//` or a trailing `/`)".to_owned()),
            "." => return Err("no `.` component; write the normalized path".to_owned()),
            ".." => return Err("no `..` component; a path may not climb out".to_owned()),
            // Windows drops trailing dots and spaces, so `.. ` or `...` would
            // read as `..` there.
            _ if component.ends_with(['.', ' ']) => {
                return Err("no component may end with `.` or a space".to_owned());
            }
            _ => {}
        }
    }
    Ok(())
}
