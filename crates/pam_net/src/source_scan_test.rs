//! The source of this crate never spells an option that weakens
//! certificate verification or widens trust, so adding one is a failing
//! change, not a review question.

use std::path::Path;

/// Spellings that must not appear in any non-test source file of this
/// crate, as curl options or as command-line flags.
const FORBIDDEN_SPELLINGS: [&str; 12] = [
    "insecure",
    "ssl-no-revoke",
    "ssl-revoke-best-effort",
    "ssl-allow-beast",
    "capath",
    "ca-native",
    "proxy-ca-native",
    "doh-insecure",
    "tlsv1.0",
    "tlsv1.1",
    "ssl-auto-client-cert",
    "proto-default",
];

#[test]
fn no_source_file_spells_an_option_that_weakens_verification() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut scanned = 0;
    for entry in std::fs::read_dir(&src).expect("the src directory lists") {
        let path = entry.expect("a directory entry").path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if path.extension().is_none_or(|ext| ext != "rs") || name.ends_with("_test.rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .expect("a source file reads")
            .to_ascii_lowercase();
        for spelling in FORBIDDEN_SPELLINGS {
            assert!(
                !text.contains(spelling),
                "{name} spells `{spelling}`; the launcher never relaxes verification"
            );
        }
        scanned += 1;
    }
    assert!(scanned >= 7, "only {scanned} source files scanned");
}
