//! `${…}` variables: what a flow file may reference, and how the daemon
//! fills them in.
//!
//! Four families exist: `${inputs.<name>}`, `${repo.path}` /`${repo.name}` /
//! `${repo.origin}`, `${steps.<id>.result.<pointer>}` and
//! `${steps.<id>.exit_status}`. Everything here is pure: the daemon builds a
//! [`Vars`], the engine calls [`substitute`] per argument string, and
//! validation calls [`references`] to reject a name no step could ever fill.
//!
//! Substitution happens once per string. A value that itself contains
//! `${…}` is copied verbatim, never expanded again, so an input can never
//! smuggle a reference to another step's secret-shaped result.

use std::collections::BTreeMap;

use serde_json::Value;
use thiserror::Error;

/// Why a `${…}` reference could not be filled in.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum VarError {
    /// Nothing in the [`Vars`] answers to this key.
    #[error("`${{{key}}}` has no value")]
    Unresolved {
        /// The key as written, without the `${` `}` wrapper.
        key: String,
    },
}

/// The values a flow run may reference.
///
/// Plain keys (`inputs.repo`, `repo.path`) hold strings; step keys hold the
/// step's JSON — `{ "result": …, "exit_status": … }` — so
/// `steps.<id>.result.jobs[0].id` walks straight into it.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vars {
    map: BTreeMap<String, String>,
    steps: BTreeMap<String, Value>,
}

impl Vars {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a plain value, e.g. `set("inputs.repo", "ro-ag/pam")`.
    pub fn set(&mut self, key: &str, value: impl Into<String>) {
        self.map.insert(key.to_string(), value.into());
    }

    /// Records a finished step's JSON, `{ "result": …, "exit_status": … }`.
    pub fn set_step(&mut self, id: &str, value: Value) {
        self.steps.insert(id.to_string(), value);
    }

    /// Resolves one key, `None` when nothing answers to it or the value is
    /// not a scalar.
    #[must_use]
    pub fn resolve(&self, key: &str) -> Option<String> {
        let Some(rest) = key.strip_prefix("steps.") else {
            return self.map.get(key).cloned();
        };
        let (id, pointer) = rest.split_once('.')?;
        let value = self.steps.get(id)?;
        scalar(walk(value, pointer)?)
    }
}

/// Every `${…}` key in `text`, in the order they appear, duplicates kept.
///
/// An unterminated `${` is ordinary text, not a reference.
#[must_use]
pub fn references(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("${") {
        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else {
            break;
        };
        found.push(after[..end].to_string());
        rest = &after[end + 1..];
    }
    found
}

/// Replaces every `${…}` in `text` with its value.
///
/// The replacement is literal: the text around the references and the
/// substituted values are both copied as-is, and the result is never
/// scanned again.
pub fn substitute(text: &str, vars: &Vars) -> Result<String, VarError> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("${") {
        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else {
            break;
        };
        let key = &after[..end];
        let value = vars.resolve(key).ok_or_else(|| VarError::Unresolved {
            key: key.to_string(),
        })?;
        out.push_str(&rest[..start]);
        out.push_str(&value);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Why a command line could not be built from its template.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ArgvError {
    /// A `${…}` reference in `run[position]` had no value.
    #[error("run[{position}]: {source}")]
    Unresolved {
        /// Index into the step's `run` array.
        position: usize,
        /// The reference that could not be filled in.
        source: VarError,
    },
    /// A substituted value would have become a command-line option.
    #[error(
        "run[{position}] would start with `-` once its variables are filled in, so the \
         program would read a supplied value as an option"
    )]
    Option {
        /// Index into the step's `run` array.
        position: usize,
    },
}

/// Fills in a command step's `run` array, refusing option injection.
///
/// A value that arrives from outside the flow file — an input, a connector
/// result, an earlier step — must not be able to turn an operand into an
/// option (`rev=--output=/path`, `script=-e …`). An argument is refused when
/// its template *begins* with a reference and the finished argument begins
/// with `-`, unless the template marks the position itself:
///
/// - a literal `--` earlier in `run` ends option parsing, so everything after
///   it is an operand whatever it looks like;
/// - literal text in front of the reference (`--since=${inputs.day}`,
///   `-${inputs.level}`) is the author spelling the option, with the value
///   confined to its argument.
///
/// The program name (`run[0]`) never carries a reference; validation refuses
/// one.
///
/// # Errors
///
/// [`ArgvError::Unresolved`] for a reference with no value, and
/// [`ArgvError::Option`] for the refusal above.
pub fn substitute_argv(argv: &[String], vars: &Vars) -> Result<Vec<String>, ArgvError> {
    let mut operands_only = false;
    let mut out = Vec::with_capacity(argv.len());
    for (position, template) in argv.iter().enumerate() {
        let argument = substitute(template, vars)
            .map_err(|source| ArgvError::Unresolved { position, source })?;
        if !operands_only && template.starts_with("${") && argument.starts_with('-') {
            return Err(ArgvError::Option { position });
        }
        // Only the author's own `--` counts; a substituted one is data.
        if template == "--" {
            operands_only = true;
        }
        out.push(argument);
    }
    Ok(out)
}

/// Walks `pointer` (`result.jobs[0].id`) into a JSON value.
fn walk<'a>(value: &'a Value, pointer: &str) -> Option<&'a Value> {
    let mut current = value;
    for segment in segments(pointer)? {
        current = match segment {
            Segment::Field(name) => current.as_object()?.get(name)?,
            Segment::Index(index) => current.as_array()?.get(index)?,
        };
    }
    Some(current)
}

pub(crate) enum Segment<'a> {
    Field(&'a str),
    Index(usize),
}

/// Splits `result.jobs[0].id` into field and index segments. `None` when the
/// pointer is malformed (an empty field, an unclosed or non-numeric index).
/// Validation runs the same split over a flow's `${steps.<id>.result.…}`
/// tails, so a pointer that could never resolve is refused before a run.
pub(crate) fn segments(pointer: &str) -> Option<Vec<Segment<'_>>> {
    let mut out = Vec::new();
    let mut rest = pointer;
    loop {
        let end = rest.find(['.', '[']).unwrap_or(rest.len());
        if end == 0 {
            return None;
        }
        out.push(Segment::Field(&rest[..end]));
        rest = &rest[end..];
        while let Some(after) = rest.strip_prefix('[') {
            let close = after.find(']')?;
            out.push(Segment::Index(after[..close].parse().ok()?));
            rest = &after[close + 1..];
        }
        match rest.strip_prefix('.') {
            Some(next) => rest = next,
            None if rest.is_empty() => return Some(out),
            None => return None,
        }
    }
}

/// Scalars stringify; arrays, objects and null do not resolve.
fn scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}
