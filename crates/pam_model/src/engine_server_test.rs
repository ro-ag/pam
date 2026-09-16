use super::{MIN_OUTPUT_TOKENS, fresh_api_key, output_budget};

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

#[test]
fn every_load_gets_a_fresh_full_length_hex_key() {
    let path = std::path::Path::new("/models/fake.gguf");
    let first = fresh_api_key(path).unwrap();
    let second = fresh_api_key(path).unwrap();
    for key in [&first, &second] {
        assert_eq!(key.len(), 64, "{key}");
        assert!(key.bytes().all(|b| b.is_ascii_hexdigit()), "{key}");
        assert!(key.bytes().any(|b| b != b'0'), "{key}");
    }
    assert_ne!(first, second, "two loads of one path never share a key");
}
