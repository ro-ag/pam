use super::input_type::{
    InputType, MAX_ENUM_VALUE_BYTES, MAX_ENUM_VALUES, MAX_INT, MAX_PATH_BYTES, MAX_REF_BYTES,
};
use super::schema::Input;

fn input(kind: InputType, values: &[&str]) -> Input {
    Input {
        description: String::new(),
        default: None,
        kind,
        values: values.iter().map(|value| (*value).to_owned()).collect(),
    }
}

/// Runs every value against one type and compares accept/refuse.
fn expect(kind: InputType, values: &[&str], accepted: &[&str], refused: &[(&str, &str)]) {
    let declared = input(kind, values);
    for value in accepted {
        declared
            .check("subject", value)
            .unwrap_or_else(|error| panic!("{value:?} should be a valid {kind:?}: {error}"));
    }
    for (value, rule) in refused {
        let error = declared
            .check("subject", value)
            .expect_err(&format!("{value:?} should break {kind:?}"));
        assert_eq!(error.input, "subject");
        let text = error.to_string();
        assert!(text.starts_with("input `subject` must be "), "{text}");
        assert!(text.contains(rule), "{value:?}: {text}");
        // The refusal never repeats the value, hostile or not.
        if value.len() > 3 {
            assert!(!text.contains(value), "{text}");
        }
    }
}

#[test]
fn a_string_input_accepts_anything() {
    let declared = input(InputType::String, &[]);
    for value in ["", "-rf", "a b", "--upload-pack=x", "\0", "${inputs.x}"] {
        assert!(declared.check("subject", value).is_ok(), "{value:?}");
    }
}

#[test]
fn the_default_type_is_string() {
    assert_eq!(InputType::default(), InputType::String);
    assert!(InputType::String.is_string());
    assert_eq!(InputType::Ref.as_str(), "ref");
}

#[test]
fn int_accepts_plain_decimals_and_refuses_everything_else() {
    let max = MAX_INT.to_string();
    let above = (MAX_INT + 1).to_string();
    let huge = "9".repeat(5000);
    expect(
        InputType::Int,
        &[],
        &["0", "7", "42", "1234567890123", &max],
        &[
            ("", "empty"),
            ("-1", "only the digits"),
            ("+1", "only the digits"),
            (" 1", "only the digits"),
            ("1 ", "only the digits"),
            ("1_000", "only the digits"),
            ("1.5", "only the digits"),
            ("0x10", "only the digits"),
            ("١٢٣", "only the digits"),
            ("1\0", "only the digits"),
            ("--output=x", "only the digits"),
            ("007", "leading zeros"),
            ("00", "leading zeros"),
            (&above, "above the limit"),
            ("99999999999999999999999", "above the limit"),
            (&huge, "above the limit"),
        ],
    );
}

#[test]
fn sha_is_forty_or_sixty_four_lowercase_hex_digits() {
    let forty = "a".repeat(40);
    let sixty_four = "0123456789abcdef".repeat(4);
    let upper = "A".repeat(40);
    let mixed = format!("{}B", "a".repeat(39));
    let zero40 = "0".repeat(40);
    let zero64 = "0".repeat(64);
    let long = "a".repeat(5000);
    expect(
        InputType::Sha,
        &[],
        &[
            &forty,
            &sixty_four,
            "0123456789abcdef0123456789abcdef01234567",
        ],
        &[
            ("", "exactly 40 or 64"),
            ("abc123", "exactly 40 or 64"),
            ("HEAD", "exactly 40 or 64"),
            (&"a".repeat(41), "exactly 40 or 64"),
            (&"a".repeat(63), "exactly 40 or 64"),
            (&long, "exactly 40 or 64"),
            (&upper, "only lowercase hexadecimal digits"),
            (&mixed, "only lowercase hexadecimal digits"),
            (
                &format!("{}g", "a".repeat(39)),
                "only lowercase hexadecimal digits",
            ),
            (
                &format!("{}\0", "a".repeat(39)),
                "only lowercase hexadecimal digits",
            ),
            (
                &format!("--upload-pack={}", "a".repeat(26)),
                "only lowercase hexadecimal digits",
            ),
            (&zero40, "all-zero"),
            (&zero64, "all-zero"),
        ],
    );
}

#[test]
fn ref_follows_git_check_ref_format() {
    let longest = "a".repeat(MAX_REF_BYTES);
    let too_long = "a".repeat(MAX_REF_BYTES + 1);
    expect(
        InputType::Ref,
        &[],
        &[
            "main",
            "HEAD",
            "v1.2.3",
            "feature/x",
            "refs/heads/feat/review-remainder",
            "refs/tags/v1.0.0-rc.1",
            "user/topic_branch",
            "a{b",
            "ünïcode/branch",
            "x.lockfile",
            &longest,
        ],
        &[
            ("", "empty"),
            ("--upload-pack=x", "start with `-`"),
            ("-b", "start with `-`"),
            ("HEAD@{1}", "@{"),
            ("@{-1}", "@{"),
            ("@", "`@` alone"),
            ("a..b", "`..`"),
            ("../../etc", "`..`"),
            ("a b", "is not allowed in a ref name"),
            ("a~1", "is not allowed in a ref name"),
            ("a^", "is not allowed in a ref name"),
            ("a:b", "is not allowed in a ref name"),
            ("a?", "is not allowed in a ref name"),
            ("a*", "is not allowed in a ref name"),
            ("a[0]", "is not allowed in a ref name"),
            ("a\\b", "is not allowed in a ref name"),
            ("a\0b", "control"),
            ("a\nb", "control"),
            ("a\x7fb", "control"),
            ("a\tb", "control"),
            ("/a", "`/`"),
            ("a/", "`/`"),
            ("a//b", "`/`"),
            ("a.", "end with `.`"),
            (".hidden", "start with `.`"),
            ("a/.b", "start with `.`"),
            ("branch.lock", "end with `.lock`"),
            ("branch.LOCK", "end with `.lock`"),
            ("a.lock/b", "end with `.lock`"),
            (&too_long, "longer than"),
        ],
    );
}

#[test]
fn path_is_relative_and_normalized() {
    let longest = "a".repeat(MAX_PATH_BYTES);
    let too_long = "a".repeat(MAX_PATH_BYTES + 1);
    expect(
        InputType::Path,
        &[],
        &[
            "Cargo.toml",
            "crates/pam_flow/src/lib.rs",
            "docs/a b.md",
            ".github/workflows/ci.yml",
            "a/.hidden",
            "a..b",
            &longest,
        ],
        &[
            ("", "empty"),
            ("/etc/passwd", "absolute"),
            ("\\Windows", "absolute"),
            ("C:/Windows", "`\\` and `:`"),
            ("C:\\Windows", "`\\` and `:`"),
            ("a\\b", "`\\` and `:`"),
            ("file:stream", "`\\` and `:`"),
            ("../../etc", "`..`"),
            ("..", "`..`"),
            ("a/../b", "`..`"),
            ("a/..", "`..`"),
            ("./a", "`.` component"),
            ("a/./b", "`.` component"),
            (".", "`.` component"),
            ("a//b", "empty component"),
            ("a/", "empty component"),
            ("-rf", "start with `-`"),
            ("--output=x", "start with `-`"),
            ("a/... ", "end with `.` or a space"),
            ("a/...", "end with `.` or a space"),
            ("a/.. ", "end with `.` or a space"),
            ("a/b ", "end with `.` or a space"),
            ("a\0b", "control"),
            ("\0", "control"),
            ("a\nb", "control"),
            (&too_long, "longer than"),
        ],
    );
}

#[test]
fn enum_accepts_only_the_listed_values() {
    expect(
        InputType::Enum,
        &["debug", "release"],
        &["debug", "release"],
        &[
            ("", "not one of debug, release"),
            ("Debug", "not one of debug, release"),
            ("debug ", "not one of debug, release"),
            ("release\0", "not one of debug, release"),
            ("--release", "not one of debug, release"),
        ],
    );
}

#[test]
fn an_enum_declaration_is_checked() {
    use super::input_type::check_declaration;
    let owned = |items: &[&str]| {
        items
            .iter()
            .map(|item| (*item).to_owned())
            .collect::<Vec<_>>()
    };
    assert!(check_declaration(InputType::Enum, &owned(&["a", "b"])).is_ok());
    assert!(check_declaration(InputType::Int, &[]).is_ok());
    for (kind, values, message) in [
        (InputType::Enum, owned(&[]), "non-empty"),
        (InputType::String, owned(&["a"]), "belongs to"),
        (InputType::Int, owned(&["a"]), "belongs to"),
        (InputType::Enum, owned(&["a", "a"]), "repeats"),
        (InputType::Enum, owned(&[""]), "1 to"),
        (InputType::Enum, owned(&[" a"]), "whitespace"),
        (InputType::Enum, owned(&["a\nb"]), "control"),
        (
            InputType::Enum,
            vec!["x".repeat(MAX_ENUM_VALUE_BYTES + 1)],
            "1 to",
        ),
        (
            InputType::Enum,
            (0..=MAX_ENUM_VALUES).map(|n| n.to_string()).collect(),
            "limit",
        ),
    ] {
        let error = check_declaration(kind, &values).expect_err(message);
        assert!(error.contains(message), "{error}");
    }
}
