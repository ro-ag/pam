use std::time::Duration;

use super::duration::{DurationError, format_duration, parse_duration};

#[test]
fn parses_every_unit() {
    assert_eq!(parse_duration("500ms"), Ok(Duration::from_millis(500)));
    assert_eq!(parse_duration("60s"), Ok(Duration::from_mins(1)));
    assert_eq!(parse_duration("2m"), Ok(Duration::from_mins(2)));
    assert_eq!(parse_duration("1h"), Ok(Duration::from_hours(1)));
    assert_eq!(parse_duration("0s"), Ok(Duration::ZERO));
}

#[test]
fn tolerates_surrounding_space() {
    assert_eq!(parse_duration("  30s "), Ok(Duration::from_secs(30)));
}

#[test]
fn rejects_a_bare_number() {
    assert_eq!(parse_duration("60"), Err(DurationError::Malformed));
}

#[test]
fn rejects_fractions_and_signs() {
    assert_eq!(parse_duration("1.5s"), Err(DurationError::Malformed));
    assert_eq!(parse_duration("-5s"), Err(DurationError::Malformed));
    assert_eq!(parse_duration("+5s"), Err(DurationError::Malformed));
}

#[test]
fn rejects_empty_and_unknown_units() {
    assert_eq!(parse_duration(""), Err(DurationError::Malformed));
    assert_eq!(parse_duration("s"), Err(DurationError::Malformed));
    assert_eq!(parse_duration("5d"), Err(DurationError::Malformed));
    assert_eq!(parse_duration("5 s"), Err(DurationError::Malformed));
    assert_eq!(parse_duration("5S"), Err(DurationError::Malformed));
}

#[test]
fn reports_overflow_instead_of_wrapping() {
    assert_eq!(
        parse_duration("99999999999999999999h"),
        Err(DurationError::Overflow)
    );
}

#[test]
fn formats_the_shortest_exact_unit() {
    assert_eq!(format_duration(Duration::from_millis(500)), "500ms");
    assert_eq!(format_duration(Duration::from_secs(45)), "45s");
    assert_eq!(format_duration(Duration::from_mins(2)), "2m");
    assert_eq!(format_duration(Duration::from_hours(1)), "1h");
    assert_eq!(format_duration(Duration::from_mins(90)), "90m");
    assert_eq!(format_duration(Duration::ZERO), "0s");
    assert_eq!(format_duration(Duration::from_micros(1500)), "1ms");
}

#[test]
fn round_trips_through_both_directions() {
    for text in ["500ms", "1s", "45s", "2m", "90m", "1h", "0s"] {
        let parsed = parse_duration(text).expect("valid duration");
        assert_eq!(format_duration(parsed), text);
    }
}

#[test]
fn error_messages_name_the_expected_shape() {
    assert!(DurationError::Malformed.to_string().contains("500ms"));
    assert!(DurationError::Overflow.to_string().contains("large"));
}
