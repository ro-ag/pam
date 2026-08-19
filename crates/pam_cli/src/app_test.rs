use std::path::Path;

use crate::{
    app::{audit_export, model_import, model_import_resource, retention_prune},
    command::RetentionScopeArg,
    render::EXIT_OPERATION_FAILED,
};

use pam_core::ContentDigest;
use pam_model::{LicenseSnapshot, ModelDescriptor, ModelKey};

fn import_descriptor(
    model_name: &str,
    filename: &str,
    size_bytes: u64,
    weights_byte: u8,
    license_id: &str,
    license_url: &str,
    license_byte: u8,
) -> ModelDescriptor {
    ModelDescriptor::new(
        ModelKey::new("vendor", model_name).unwrap(),
        filename,
        ContentDigest::from_sha256([weights_byte; 32]),
        size_bytes,
        LicenseSnapshot::new(
            license_id,
            license_url,
            ContentDigest::from_sha256([license_byte; 32]),
        )
        .unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn administrative_storage_ranges_are_rejected_before_local_authorization() {
    assert_eq!(
        audit_export(Path::new("unused-audit-output"), u64::MAX, None, None, 1).await,
        EXIT_OPERATION_FAILED
    );
    assert_eq!(
        audit_export(Path::new("unused-audit-output"), 0, Some(u64::MAX), None, 1,).await,
        EXIT_OPERATION_FAILED
    );
    assert_eq!(
        retention_prune(RetentionScopeArg::Session, u64::MAX, None, 1).await,
        EXIT_OPERATION_FAILED
    );
}

#[tokio::test]
async fn model_import_requires_explicit_license_acceptance_before_path_or_store_access() {
    assert_eq!(
        model_import(
            ModelKey::new("vendor", "model").unwrap(),
            Path::new("/definitely/missing/model.gguf"),
            ContentDigest::from_sha256([1; 32]),
            24,
            "Apache-2.0".to_owned(),
            "https://example.test/LICENSE".to_owned(),
            ContentDigest::from_sha256([2; 32]),
            false,
            None,
        )
        .await,
        EXIT_OPERATION_FAILED
    );
}

#[test]
fn model_import_approval_resource_binds_every_immutable_import_effect_field() {
    let baseline = import_descriptor(
        "model",
        "weights.gguf",
        24,
        1,
        "Apache-2.0",
        "https://example.test/LICENSE",
        2,
    );
    let baseline_resource = model_import_resource(&baseline);
    assert!(
        baseline_resource
            .as_str()
            .contains("model:vendor/model:import-effect=sha256:")
    );
    for sensitive in ["weights.gguf", "Apache-2.0", "https://example.test/LICENSE"] {
        assert!(!baseline_resource.as_str().contains(sensitive));
    }

    for changed in [
        import_descriptor(
            "other",
            "weights.gguf",
            24,
            1,
            "Apache-2.0",
            "https://example.test/LICENSE",
            2,
        ),
        import_descriptor(
            "model",
            "other.gguf",
            24,
            1,
            "Apache-2.0",
            "https://example.test/LICENSE",
            2,
        ),
        import_descriptor(
            "model",
            "weights.gguf",
            25,
            1,
            "Apache-2.0",
            "https://example.test/LICENSE",
            2,
        ),
        import_descriptor(
            "model",
            "weights.gguf",
            24,
            3,
            "Apache-2.0",
            "https://example.test/LICENSE",
            2,
        ),
        import_descriptor(
            "model",
            "weights.gguf",
            24,
            1,
            "MIT",
            "https://example.test/LICENSE",
            2,
        ),
        import_descriptor(
            "model",
            "weights.gguf",
            24,
            1,
            "Apache-2.0",
            "https://example.test/OTHER-LICENSE",
            2,
        ),
        import_descriptor(
            "model",
            "weights.gguf",
            24,
            1,
            "Apache-2.0",
            "https://example.test/LICENSE",
            4,
        ),
    ] {
        assert_ne!(baseline_resource, model_import_resource(&changed));
    }
}
