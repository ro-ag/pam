//! Durations as flow YAML writes them: an integer and a unit, `500ms`,
//! `60s`, `2m`, `1h`.
//!
//! Flow files never carry fractions or bare numbers: a step timeout and a
//! retry backoff always name their unit, so a human reading the YAML cannot
//! mistake seconds for milliseconds. [`format_duration`] is the exact
//! inverse for every value [`parse_duration`] accepts.

use std::time::Duration;

use thiserror::Error;

/// Why a duration string could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DurationError {
    /// The text is not an unsigned integer followed by `ms`, `s`, `m` or `h`.
    #[error("expected a duration like `500ms`, `60s`, `2m` or `1h`")]
    Malformed,
    /// The value is well formed but too large to represent.
    #[error("the duration is too large")]
    Overflow,
}

const MILLIS_PER_SECOND: u64 = 1_000;
const SECONDS_PER_MINUTE: u64 = 60;
const SECONDS_PER_HOUR: u64 = 3_600;

/// Reads `500ms`, `60s`, `2m` or `1h` into a [`Duration`].
///
/// Surrounding whitespace is ignored. A bare number, a fraction, a sign, an
/// unknown unit, or a space between the number and the unit is
/// [`DurationError::Malformed`].
///
/// ```
/// use std::time::Duration;
/// assert_eq!(pam_flow::parse_duration("2m"), Ok(Duration::from_mins(2)));
/// ```
pub fn parse_duration(text: &str) -> Result<Duration, DurationError> {
    let trimmed = text.trim();
    let digits_end = trimmed
        .find(|c: char| !c.is_ascii_digit())
        .ok_or(DurationError::Malformed)?;
    if digits_end == 0 {
        return Err(DurationError::Malformed);
    }
    let (digits, unit) = trimmed.split_at(digits_end);
    let value: u64 = digits.parse().map_err(|_| DurationError::Overflow)?;
    let millis = match unit {
        "ms" => Some(value),
        "s" => value.checked_mul(MILLIS_PER_SECOND),
        "m" => value.checked_mul(SECONDS_PER_MINUTE * MILLIS_PER_SECOND),
        "h" => value.checked_mul(SECONDS_PER_HOUR * MILLIS_PER_SECOND),
        _ => return Err(DurationError::Malformed),
    };
    millis
        .map(Duration::from_millis)
        .ok_or(DurationError::Overflow)
}

/// Renders a duration in the largest unit that keeps it exact.
///
/// Sub-millisecond precision is truncated: flow YAML has no way to express
/// it, and every duration the schema produces is a whole number of
/// milliseconds.
///
/// ```
/// use std::time::Duration;
/// assert_eq!(pam_flow::format_duration(Duration::from_mins(2)), "2m");
/// ```
#[must_use]
pub fn format_duration(duration: Duration) -> String {
    let millis = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
    if millis == 0 {
        return "0s".to_string();
    }
    if !millis.is_multiple_of(MILLIS_PER_SECOND) {
        return format!("{millis}ms");
    }
    let seconds = millis / MILLIS_PER_SECOND;
    if seconds.is_multiple_of(SECONDS_PER_HOUR) {
        return format!("{}h", seconds / SECONDS_PER_HOUR);
    }
    if seconds.is_multiple_of(SECONDS_PER_MINUTE) {
        return format!("{}m", seconds / SECONDS_PER_MINUTE);
    }
    format!("{seconds}s")
}
