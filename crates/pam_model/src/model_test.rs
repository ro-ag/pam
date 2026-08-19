use pam_core::ContentDigest;

use super::{LicenseConsent, LicenseSnapshot, ModelDescriptor, ModelError, ModelKey, ModelSource};

fn digest(byte: u8) -> ContentDigest {
    ContentDigest::from_sha256([byte; 32])
}

#[test]
fn model_identity_accepts_only_bounded_path_segments() {
    assert_eq!(
        ModelKey::new("qwen", "qwen3.6-35b").unwrap().id(),
        "qwen/qwen3.6-35b"
    );
    for value in ["", ".", "..", "a/b", "a\\b", "with space", "\n"] {
        assert!(matches!(
            ModelKey::new(value, "model"),
            Err(ModelError::InvalidModelIdentity)
        ));
        assert!(matches!(
            ModelKey::new("vendor", value),
            Err(ModelError::InvalidModelIdentity)
        ));
    }
}

fn descriptor(digest_byte: u8, license_digest_byte: u8, size_bytes: u64) -> ModelDescriptor {
    ModelDescriptor::new(
        ModelKey::new("vendor", "model").unwrap(),
        "model.gguf",
        digest(digest_byte),
        size_bytes,
        LicenseSnapshot::new(
            "Apache-2.0",
            "https://example.test/license",
            digest(license_digest_byte),
        )
        .unwrap(),
    )
    .unwrap()
}

#[test]
fn consent_is_bound_to_the_full_model_descriptor() {
    let first = descriptor(1, 2, ModelDescriptor::MIN_SIZE_BYTES);
    let consent = LicenseConsent::accept(&first);
    assert!(consent.verify(&first).is_ok());

    let mut changed_key = first.clone();
    changed_key.key = ModelKey::new("other", "model").unwrap();
    let mut changed_filename = first.clone();
    changed_filename.filename = "other.gguf".to_owned();
    for changed in [
        changed_key,
        changed_filename,
        descriptor(3, 2, ModelDescriptor::MIN_SIZE_BYTES),
        descriptor(1, 3, ModelDescriptor::MIN_SIZE_BYTES),
        descriptor(1, 2, ModelDescriptor::MIN_SIZE_BYTES + 1),
    ] {
        assert!(matches!(
            consent.verify(&changed),
            Err(ModelError::LicenseNotAccepted)
        ));
    }
}

#[test]
fn descriptor_enforces_bounded_model_size() {
    assert_eq!(
        descriptor(1, 2, ModelDescriptor::MIN_SIZE_BYTES).expected_size_bytes,
        ModelDescriptor::MIN_SIZE_BYTES
    );
    assert_eq!(
        descriptor(1, 2, ModelDescriptor::MAX_SIZE_BYTES).expected_size_bytes,
        ModelDescriptor::MAX_SIZE_BYTES
    );
    for size_bytes in [
        ModelDescriptor::MIN_SIZE_BYTES - 1,
        ModelDescriptor::MAX_SIZE_BYTES + 1,
    ] {
        assert!(matches!(
            ModelDescriptor::new(
                ModelKey::new("vendor", "model").unwrap(),
                "model.gguf",
                digest(1),
                size_bytes,
                LicenseSnapshot::new("Apache-2.0", "https://example.test/license", digest(2),)
                    .unwrap(),
            ),
            Err(ModelError::InvalidContentLength)
        ));
    }
}

#[test]
fn license_metadata_rejects_insecure_or_credentialed_links() {
    for url in [
        "http://example.test/license",
        " https://example.test/license",
        "https://token@example.test/license",
        "https://example.test:8443/license",
        "https://example.test/license?token=secret",
        "https://example.test/license#secret",
    ] {
        assert!(matches!(
            LicenseSnapshot::new("license", url, digest(1)),
            Err(ModelError::InvalidLicense)
        ));
    }

    let prefix = "https://example.test/";
    let maximum = format!("{prefix}{}", "a".repeat(2048 - prefix.len()));
    assert!(LicenseSnapshot::new("license", maximum, digest(1)).is_ok());
    let oversized = format!("{prefix}{}", "a".repeat(2049 - prefix.len()));
    assert!(matches!(
        LicenseSnapshot::new("license", oversized, digest(1)),
        Err(ModelError::InvalidLicense)
    ));
}

#[test]
fn durable_https_source_requires_a_canonical_public_identity() {
    let source = ModelSource::https("https://models.example/model.gguf").unwrap();
    assert_eq!(source.identity(), Some("https://models.example/model.gguf"));
    for invalid in [
        "https:// ",
        "http://models.example/model.gguf",
        "https://models.example:8443/model.gguf",
        "https://models.example/model.gguf?token=secret",
        "https://models.example/model.gguf#fragment",
        "https://models.example",
    ] {
        assert!(matches!(
            ModelSource::https(invalid),
            Err(ModelError::InvalidSource)
        ));
    }
}
