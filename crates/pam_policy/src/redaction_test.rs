use super::{
    MAX_AUDIT_DETAIL_INPUT_BYTES, MAX_AUDIT_DETAIL_OUTPUT_BYTES, REDACTION_MARKER,
    TRUNCATION_MARKER, redact_audit_detail,
};

fn assert_absent(output: &str, secrets: &[&str]) {
    for secret in secrets {
        assert!(
            !output.contains(secret),
            "redacted output retained recognizable secret {secret:?}: {output}"
        );
    }
}

#[test]
fn authorization_schemes_and_cookie_headers_are_case_insensitive_and_crlf_safe() {
    let input = b"aUtHoRiZaTiOn: Bearer HeaderSecret\r\n\
        PROXY-AUTHORIZATION: Basic ProxySecret\r\n\
        Cookie: session=CookieSecret\r\n\
        sEt-CoOkIe: refresh=SetCookieSecret; Secure\r\n\
        loose Bearer LooseSecret and Basic QWxhZGRpbjpPcGVuU2VzYW1l";

    let output = redact_audit_detail(input);

    assert_absent(
        &output,
        &[
            "HeaderSecret",
            "ProxySecret",
            "CookieSecret",
            "SetCookieSecret",
            "LooseSecret",
            "QWxhZGRpbjpPcGVuU2VzYW1l",
        ],
    );
    assert!(output.matches(REDACTION_MARKER).count() >= 6);
    assert!(!output.contains('\r'));
    assert!(!output.contains('\n'));
}

#[test]
fn folded_sensitive_headers_conservatively_redact_the_remaining_tail() {
    let cases = [
        ("Authorization", "Bearer", "FoldedAuthorizationSecret"),
        (
            "Proxy-Authorization",
            "Basic",
            "FoldedProxyAuthorizationSecret",
        ),
        ("Cookie", "session=", "FoldedCookieSecret"),
    ];

    for (header, prefix, secret) in cases {
        let input = format!("{header}: {prefix}\r\n\t{secret}\r\nvisible tail");

        let output = redact_audit_detail(input.as_bytes());
        let repeated = redact_audit_detail(output.as_bytes());

        assert_absent(&output, &[secret, "visible tail"]);
        assert_eq!(output, repeated);
        assert!(output.ends_with(REDACTION_MARKER));
        assert!(output.len() <= MAX_AUDIT_DETAIL_OUTPUT_BYTES);
    }
}

#[test]
fn incomplete_sensitive_headers_consume_unindented_crlf_tail() {
    let cases = [
        (
            "Authorization: Bearer\r\nLeakedAuthorizationSecret",
            "LeakedAuthorizationSecret",
        ),
        (
            "Proxy-Authorization: Basic\nLeakedProxySecret",
            "LeakedProxySecret",
        ),
        (
            "Cookie: session=\r\nLeakedCookieSecret",
            "LeakedCookieSecret",
        ),
        (
            "Set-Cookie:\rLeakedSetCookieSecret",
            "LeakedSetCookieSecret",
        ),
    ];

    for (input, secret) in cases {
        let output = redact_audit_detail(input.as_bytes());
        let repeated = redact_audit_detail(output.as_bytes());

        assert_absent(&output, &[secret]);
        assert_eq!(output, repeated);
        assert_eq!(output, REDACTION_MARKER);
        assert!(output.len() <= MAX_AUDIT_DETAIL_OUTPUT_BYTES);
    }
}

#[test]
fn complete_sensitive_headers_remain_line_scoped_and_idempotent() {
    let input = b"Authorization: Bearer CompleteAuthorizationSecret\r\n\
        Cookie: session=CompleteCookieSecret\r\n\
        visible tail";

    let output = redact_audit_detail(input);
    let repeated = redact_audit_detail(output.as_bytes());

    assert_absent(
        &output,
        &["CompleteAuthorizationSecret", "CompleteCookieSecret"],
    );
    assert!(output.contains("visible tail"));
    assert_eq!(output, repeated);
    assert_eq!(output.matches(REDACTION_MARKER).count(), 2);
    assert!(output.len() <= MAX_AUDIT_DETAIL_OUTPUT_BYTES);
}

#[test]
fn proxy_userinfo_and_common_query_secrets_are_redacted_without_hiding_safe_values() {
    let input = b"proxy=https://alice:p%40ssword@proxy.example.test:8443/path \
        socks5://bob:ProxyTwo@localhost:1080 \
        https://service.test/run?safe=visible&access_token=QueryOne\
        &API%5FKEY=QueryTwo&signature='QueryThree'#fragment";

    let output = redact_audit_detail(input);

    assert_absent(
        &output,
        &[
            "alice",
            "p%40ssword",
            "bob",
            "ProxyTwo",
            "QueryOne",
            "QueryTwo",
            "QueryThree",
        ],
    );
    assert!(output.contains("proxy.example.test"));
    assert!(output.contains("safe=visible"));
}

#[test]
fn json_secret_fields_handle_nested_values_escaped_keys_mixed_case_and_unicode() {
    let input = r#"{
      "Password": "JsonOne",
      "nested": {"api\u005fkey": "JsonTwo", "safe": "café"},
      "ToKeN": {"raw": "JsonThree", "nested": [1, 2, 3]},
      "client-secret": null,
      "visible": "naïve"
    }"#;

    let output = redact_audit_detail(input.as_bytes());

    assert_absent(&output, &["JsonOne", "JsonTwo", "JsonThree"]);
    assert!(output.contains("café"));
    assert!(output.contains("naïve"));
    assert!(output.contains("\"safe\""));
    assert!(output.contains("\"visible\""));
}

#[test]
fn json_secret_value_after_multiline_whitespace_is_redacted_idempotently() {
    let input = b"{\"password\":\r\n\"LeakedSecret\"}";

    let output = redact_audit_detail(input);
    let repeated = redact_audit_detail(output.as_bytes());

    assert_absent(&output, &["LeakedSecret"]);
    assert_eq!(output, repeated);
    assert!(output.contains("\"password\""));
    assert!(output.len() <= MAX_AUDIT_DETAIL_OUTPUT_BYTES);
}

#[test]
fn environment_assignments_cover_suffixes_quotes_and_multiple_assignments() {
    let input = b"export SERVICE_TOKEN=EnvOne\n\
        PASSWORD='Env Two'\n\
        build.api-key=EnvThree SAFE=value OTHER_CREDENTIAL=EnvFour; next\n\
        ORDINARY_KEY=visible";

    let output = redact_audit_detail(input);

    assert_absent(&output, &["EnvOne", "Env Two", "EnvThree", "EnvFour"]);
    assert!(output.contains("SAFE=value"));
    assert!(output.contains("ORDINARY_KEY=visible"));
}

#[test]
fn private_key_blocks_are_removed_even_with_mixed_case_or_missing_end_markers() {
    let complete = b"before\n-----bEgIn encrypted private key-----\n\
        PrivateKeyMaterialOne\n-----EnD encrypted private key-----\nafter";
    let incomplete = b"prefix -----BEGIN PRIVATE KEY-----\nPrivateKeyMaterialTwo";

    let complete_output = redact_audit_detail(complete);
    let incomplete_output = redact_audit_detail(incomplete);

    assert_absent(&complete_output, &["PrivateKeyMaterialOne"]);
    assert_absent(&incomplete_output, &["PrivateKeyMaterialTwo"]);
    assert!(complete_output.contains("before"));
    assert!(complete_output.contains("after"));
    assert!(incomplete_output.starts_with("prefix "));
}

#[test]
fn jwt_shaped_tokens_are_redacted_standalone_and_inside_other_secret_ranges() {
    let first = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature_value_123";
    let second = "aaaaaaaa.bbbbbbbb.cccccccc";
    let input = format!("jwt={first} Authorization: Bearer {second}");

    let output = redact_audit_detail(input.as_bytes());

    assert_absent(&output, &[first, second, "signature_value_123"]);
    assert!(output.matches(REDACTION_MARKER).count() >= 2);
}

#[test]
fn overlapping_header_bearer_and_jwt_matches_collapse_without_leaking_fragments() {
    let token = "eyJhbGciOiJIUzI1NiJ9.eyJzZWNyZXQiOiJPdmVybGFwU2VjcmV0In0.signature123";
    let input = format!("Authorization: Bearer {token}\r\nvisible");

    let output = redact_audit_detail(input.as_bytes());

    assert_absent(&output, &[token, "T3ZlcmxhcFNlY3JldA", "signature123"]);
    assert_eq!(output.matches(REDACTION_MARKER).count(), 1);
    assert!(output.ends_with("visible"));
}

#[test]
fn arbitrary_bytes_controls_ansi_and_bidi_are_rendered_as_safe_utf8() {
    let mut input = b"visible\xff\0\x1b[31mcolored\x1b[0m\r\n".to_vec();
    input.extend_from_slice("safe\u{202e}text\u{2066}".as_bytes());
    input.extend_from_slice(b"\x9bterminal");

    let output = redact_audit_detail(&input);

    assert!(output.contains('\u{fffd}'));
    assert!(output.contains("visible"));
    assert!(output.contains("colored"));
    assert!(output.contains("safe\\u{202E}text\\u{2066}"));
    assert!(output.chars().all(|character| !character.is_control()));
    assert!(!output.contains('\0'));
    assert!(!output.contains('\u{1b}'));
    assert!(!output.contains('\u{9b}'));
}

#[test]
fn invalid_utf8_and_nul_inside_secrets_do_not_split_or_reveal_them() {
    let input = b"Authorization: Bearer BeginSecret\xff\0EndSecret\r\n\
        token=QuerySecret\xffTail";

    let output = redact_audit_detail(input);

    assert_absent(
        &output,
        &["BeginSecret", "EndSecret", "QuerySecret", "Tail"],
    );
    assert!(output.chars().all(|character| !character.is_control()));
}

#[test]
fn output_bound_is_exact_and_always_uses_an_explicit_truncation_marker() {
    let input = vec![b'a'; MAX_AUDIT_DETAIL_OUTPUT_BYTES * 2];

    let output = redact_audit_detail(&input);

    assert_eq!(output.len(), MAX_AUDIT_DETAIL_OUTPUT_BYTES);
    assert!(output.ends_with(TRUNCATION_MARKER));
}

#[test]
fn input_bound_redacts_an_unterminated_tail_before_marking_truncation() {
    let input = vec![b'S'; MAX_AUDIT_DETAIL_INPUT_BYTES + 128];

    let output = redact_audit_detail(&input);

    assert_eq!(output, format!("{REDACTION_MARKER}{TRUNCATION_MARKER}"));
    assert!(!output.contains("SSSS"));
}

#[test]
fn every_byte_value_is_panic_free_terminal_safe_and_deterministic() {
    let input = (0_u8..=u8::MAX).cycle().take(4096).collect::<Vec<_>>();

    let first = redact_audit_detail(&input);
    let second = redact_audit_detail(&input);

    assert_eq!(first, second);
    assert!(first.is_char_boundary(first.len()));
    assert!(first.chars().all(|character| !character.is_control()));
    assert!(first.len() <= MAX_AUDIT_DETAIL_OUTPUT_BYTES);
}

#[test]
fn already_redacted_output_is_stable() {
    let first = redact_audit_detail(b"api_key=StableSecret\nvisible");

    let second = redact_audit_detail(first.as_bytes());

    assert_absent(&second, &["StableSecret"]);
    assert_eq!(first, second);
}
