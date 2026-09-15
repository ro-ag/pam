use super::{MIN_OUTPUT_TOKENS, output_budget};

#[test]
fn a_tiny_positive_budget_is_raised_to_the_floor_and_zero_is_left_alone() {
    // gpt-oss's harmony template opens an analysis channel before the
    // answer; under ~16 tokens the parser never closes it and the reply is
    // raw control tokens. Zero keeps its engine meaning (no explicit cap).
    assert_eq!(MIN_OUTPUT_TOKENS, 16);
    assert_eq!(output_budget(0), 0);
    for requested in 1..MIN_OUTPUT_TOKENS {
        assert_eq!(output_budget(requested), MIN_OUTPUT_TOKENS, "{requested}");
    }
    assert_eq!(output_budget(MIN_OUTPUT_TOKENS), MIN_OUTPUT_TOKENS);
    assert_eq!(output_budget(64), 64);
}
