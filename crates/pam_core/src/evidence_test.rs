use uuid::Uuid;

use super::{ContentDigest, EvidenceHandle, EvidenceReference};

#[test]
fn evidence_handles_require_canonical_semantic_uris() {
    let uuid = Uuid::parse_str("01234567-89ab-cdef-0123-456789abcdef").unwrap();
    let handle = EvidenceHandle::from_uuid(uuid);

    assert_eq!(
        handle.as_str(),
        "evidence://pam/01234567-89ab-cdef-0123-456789abcdef"
    );
    assert_eq!(EvidenceHandle::parse(handle.to_string()).unwrap(), handle);
    assert_eq!(
        EvidenceHandle::parse("evidence://ci/1842/failure")
            .unwrap()
            .as_str(),
        "evidence://ci/1842/failure"
    );
    assert!(EvidenceHandle::parse("../blob").is_err());
    assert!(EvidenceHandle::parse("evidence://ci/../failure").is_err());
    assert!(EvidenceHandle::parse("evidence://ci/%2e%2e/failure").is_err());
    assert!(EvidenceHandle::parse("evidence://CI/1842/failure").is_err());
}

#[test]
fn content_digests_are_canonical_algorithm_qualified_values() {
    let digest = ContentDigest::from_sha256([0xab; 32]);

    assert_eq!(
        digest.as_str(),
        "sha256:abababababababababababababababababababababababababababababababab"
    );
    assert_eq!(digest.sha256_hex(), "ab".repeat(32));
    assert_eq!(ContentDigest::parse(digest.to_string()).unwrap(), digest);
    assert!(ContentDigest::parse("../blob").is_err());
    assert!(ContentDigest::parse(format!("sha256:{}", "AB".repeat(32))).is_err());
}

#[test]
fn evidence_references_keep_semantic_handles_separate_from_content_digests() {
    let reference = EvidenceReference {
        handle: EvidenceHandle::parse("evidence://ci/1842/failure").unwrap(),
        offset: 5,
        length: 8,
    };

    assert_eq!(reference.offset, 5);
    assert_eq!(reference.length, 8);
}
