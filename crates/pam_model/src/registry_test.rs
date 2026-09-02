use std::path::{Path, PathBuf};

use crate::gguf_test::{GGML_F32, GgufValue, synth_gguf, tiny_moe_gguf};
use crate::registry::{
    MODEL_FLOOR_BYTES, ModelClass, ModelEntry, Registry, RegistryError, VerifiedRecord, classify,
    default_models_dir, sha256_file, verified_sidecar_path,
};

/// A models dir with `qwen/<name>` written from `bytes`.
fn models_dir_with(name: &str, bytes: &[u8]) -> (tempfile::TempDir, Registry) {
    let dir = tempfile::tempdir().unwrap();
    let vendor = dir.path().join("qwen");
    std::fs::create_dir_all(&vendor).unwrap();
    std::fs::write(vendor.join(name), bytes).unwrap();
    let registry = Registry::new(dir.path());
    (dir, registry)
}

#[test]
fn classify_draws_the_line_at_the_floor() {
    assert_eq!(classify(MODEL_FLOOR_BYTES), ModelClass::Engine);
    assert_eq!(classify(MODEL_FLOOR_BYTES + 1), ModelClass::Engine);
    assert_eq!(classify(MODEL_FLOOR_BYTES - 1), ModelClass::TestOnly);
    assert_eq!(classify(0), ModelClass::TestOnly);
}

#[test]
fn scan_of_an_empty_dir_finds_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let registry = Registry::new(dir.path());
    assert_eq!(registry.dir(), dir.path());
    assert!(registry.scan().unwrap().is_empty());
}

#[test]
fn scan_of_a_missing_dir_finds_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let registry = Registry::new(dir.path().join("not-created-yet"));
    assert!(registry.scan().unwrap().is_empty());
}

#[test]
fn scan_of_a_file_is_not_a_directory() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("llm");
    std::fs::write(&path, b"not a dir").unwrap();
    let registry = Registry::new(&path);
    assert!(matches!(
        registry.scan(),
        Err(RegistryError::NotADirectory(_))
    ));
}

#[test]
fn scan_reads_a_models_header_and_classes_it_test_only() {
    let (_dir, registry) = models_dir_with("tiny.gguf", &tiny_moe_gguf());

    let entries = registry.scan().unwrap();
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];

    assert_eq!(entry.id, "qwen/tiny");
    assert_eq!(entry.vendor, "qwen");
    assert_eq!(entry.file_name, "tiny.gguf");
    assert_eq!(entry.class, ModelClass::TestOnly);
    assert_eq!(entry.info_error, None);
    assert_eq!(entry.verified, None);
    assert_eq!(entry.catalog_id, None);
    let info = entry.info.as_ref().expect("the header parsed");
    assert_eq!(info.architecture, "qwen3moe");
    assert_eq!(
        entry.size_bytes,
        u64::try_from(tiny_moe_gguf().len()).unwrap()
    );
}

#[test]
fn a_garbage_file_becomes_an_entry_with_a_reason() {
    let (_dir, registry) = models_dir_with("junk.gguf", b"this is not a model, it is a sentence");

    let entries = registry.scan().unwrap();
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];

    assert_eq!(entry.id, "qwen/junk");
    assert!(entry.info.is_none());
    let reason = entry.info_error.as_ref().expect("a reason is recorded");
    assert!(
        reason.to_lowercase().contains("magic"),
        "the reason should name the fault: {reason}"
    );
}

#[test]
fn scan_ignores_everything_that_is_not_a_gguf() {
    let dir = tempfile::tempdir().unwrap();
    let vendor = dir.path().join("qwen");
    std::fs::create_dir_all(&vendor).unwrap();
    std::fs::write(vendor.join("real.gguf"), tiny_moe_gguf()).unwrap();
    std::fs::write(vendor.join("notes.txt"), b"hello").unwrap();
    std::fs::write(vendor.join(".real.gguf.pam-model.part"), b"partial").unwrap();
    std::fs::write(dir.path().join("loose.gguf"), tiny_moe_gguf()).unwrap();
    std::fs::create_dir_all(vendor.join("nested")).unwrap();
    std::fs::write(vendor.join("nested").join("deep.gguf"), tiny_moe_gguf()).unwrap();

    let ids: Vec<String> = registry_ids(&Registry::new(dir.path()));
    assert_eq!(ids, vec!["qwen/real".to_owned()]);
}

#[test]
fn scan_sorts_by_id() {
    let dir = tempfile::tempdir().unwrap();
    for (vendor, name) in [("qwen", "b.gguf"), ("qwen", "a.gguf"), ("meta", "c.gguf")] {
        let vendor_dir = dir.path().join(vendor);
        std::fs::create_dir_all(&vendor_dir).unwrap();
        std::fs::write(vendor_dir.join(name), tiny_moe_gguf()).unwrap();
    }

    assert_eq!(
        registry_ids(&Registry::new(dir.path())),
        vec![
            "meta/c".to_owned(),
            "qwen/a".to_owned(),
            "qwen/b".to_owned()
        ]
    );
}

fn registry_ids(registry: &Registry) -> Vec<String> {
    registry
        .scan()
        .unwrap()
        .into_iter()
        .map(|entry| entry.id)
        .collect()
}

#[test]
fn find_hits_and_misses() {
    let (_dir, registry) = models_dir_with("tiny.gguf", &tiny_moe_gguf());

    let found = registry
        .find("qwen/tiny")
        .unwrap()
        .expect("the model is there");
    assert_eq!(found.file_name, "tiny.gguf");
    assert!(registry.find("qwen/absent").unwrap().is_none());
}

#[test]
fn dest_for_follows_the_vendor_layout() {
    let registry = Registry::new("/models");
    assert_eq!(
        registry.dest_for("qwen", "Qwen3.gguf"),
        PathBuf::from("/models").join("qwen").join("Qwen3.gguf")
    );
}

#[test]
fn verify_writes_a_sidecar_that_the_next_scan_reads_back() {
    let (_dir, registry) = models_dir_with("tiny.gguf", &tiny_moe_gguf());
    let entry = registry.find("qwen/tiny").unwrap().unwrap();

    let outcome = registry.verify(&entry).unwrap();
    assert_eq!(outcome.size_bytes, entry.size_bytes);
    assert_eq!(outcome.sha256.len(), 64);
    assert_eq!(outcome.matches_catalog, None);
    assert!(verified_sidecar_path(&entry.path).exists());

    let rescanned = registry.find("qwen/tiny").unwrap().unwrap();
    let record = rescanned.verified.expect("the sidecar is read back");
    assert_eq!(record.sha256, outcome.sha256);
    assert_eq!(record.size_bytes, entry.size_bytes);
    assert_eq!(record.matches_catalog, None);
    assert!(record.verified_ts > 0);
}

#[test]
fn verify_of_a_catalog_file_name_with_the_wrong_bytes_says_so() {
    let (_dir, registry) =
        models_dir_with("Qwen3-Coder-30B-A3B-Instruct-Q4_K_M.gguf", &tiny_moe_gguf());
    let entry = registry
        .find("qwen/Qwen3-Coder-30B-A3B-Instruct-Q4_K_M")
        .unwrap()
        .unwrap();
    assert_eq!(entry.catalog_id, Some("qwen3-coder-30b-a3b-q4_k_m"));

    let outcome = registry.verify(&entry).unwrap();
    assert_eq!(
        outcome.matches_catalog,
        Some(false),
        "a file wearing a catalog name but carrying other bytes must not pass"
    );

    let rescanned = registry
        .find("qwen/Qwen3-Coder-30B-A3B-Instruct-Q4_K_M")
        .unwrap()
        .unwrap();
    assert_eq!(
        rescanned.verified.unwrap().matches_catalog,
        Some(false),
        "and the verdict survives the sidecar round trip"
    );
}

#[test]
fn verify_of_a_vanished_file_is_not_found() {
    let (dir, registry) = models_dir_with("tiny.gguf", &tiny_moe_gguf());
    let entry = registry.find("qwen/tiny").unwrap().unwrap();
    std::fs::remove_file(dir.path().join("qwen").join("tiny.gguf")).unwrap();

    assert!(matches!(
        registry.verify(&entry),
        Err(RegistryError::NotFound(_))
    ));
}

#[test]
fn record_verified_is_what_a_finished_download_calls() {
    let (_dir, registry) = models_dir_with("tiny.gguf", &tiny_moe_gguf());
    let entry = registry.find("qwen/tiny").unwrap().unwrap();

    let record = VerifiedRecord {
        sha256: "a".repeat(64),
        size_bytes: 7,
        verified_ts: 1_700_000_000,
        matches_catalog: Some(true),
    };
    registry.record_verified(&entry.path, &record).unwrap();

    let rescanned = registry.find("qwen/tiny").unwrap().unwrap();
    assert_eq!(rescanned.verified, Some(record));
}

#[test]
fn an_unreadable_sidecar_is_ignored_rather_than_fatal() {
    let (_dir, registry) = models_dir_with("tiny.gguf", &tiny_moe_gguf());
    let entry = registry.find("qwen/tiny").unwrap().unwrap();
    std::fs::write(verified_sidecar_path(&entry.path), b"{ not json").unwrap();

    let rescanned = registry.find("qwen/tiny").unwrap().unwrap();
    assert_eq!(rescanned.verified, None);
}

#[test]
fn delete_removes_the_model_and_its_sidecar() {
    let (_dir, registry) = models_dir_with("tiny.gguf", &tiny_moe_gguf());
    let entry = registry.find("qwen/tiny").unwrap().unwrap();
    registry.verify(&entry).unwrap();
    let sidecar = verified_sidecar_path(&entry.path);
    assert!(sidecar.exists());

    registry.delete(&entry).unwrap();
    assert!(!entry.path.exists());
    assert!(!sidecar.exists());
    assert!(registry.scan().unwrap().is_empty());
}

#[test]
fn delete_refuses_a_path_outside_the_models_dir() {
    let models = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let path = elsewhere.path().join("precious.gguf");
    std::fs::write(&path, tiny_moe_gguf()).unwrap();

    let registry = Registry::new(models.path());
    let entry = entry_at(&path);

    assert!(matches!(
        registry.delete(&entry),
        Err(RegistryError::OutsideModelsDir(_))
    ));
    assert!(path.exists(), "the file outside the models dir survives");
}

#[test]
fn delete_refuses_a_traversal_back_out_of_the_models_dir() {
    let root = tempfile::tempdir().unwrap();
    let models = root.path().join("models");
    std::fs::create_dir_all(&models).unwrap();
    let path = root.path().join("precious.gguf");
    std::fs::write(&path, tiny_moe_gguf()).unwrap();

    let registry = Registry::new(&models);
    let mut entry = entry_at(&path);
    entry.path = models.join("..").join("precious.gguf");

    assert!(matches!(
        registry.delete(&entry),
        Err(RegistryError::OutsideModelsDir(_))
    ));
    assert!(path.exists(), "the traversal target survives");
}

#[test]
fn delete_of_a_vanished_file_is_not_found() {
    let (dir, registry) = models_dir_with("tiny.gguf", &tiny_moe_gguf());
    let entry = registry.find("qwen/tiny").unwrap().unwrap();
    std::fs::remove_file(dir.path().join("qwen").join("tiny.gguf")).unwrap();

    assert!(matches!(
        registry.delete(&entry),
        Err(RegistryError::NotFound(_))
    ));
}

fn entry_at(path: &Path) -> ModelEntry {
    ModelEntry {
        id: "qwen/precious".to_owned(),
        vendor: "qwen".to_owned(),
        file_name: "precious.gguf".to_owned(),
        path: path.to_path_buf(),
        size_bytes: 1,
        info: None,
        info_error: None,
        class: ModelClass::TestOnly,
        verified: None,
        catalog_id: None,
    }
}

#[test]
fn sha256_file_matches_the_known_digest() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("greeting");
    std::fs::write(&path, b"hello world").unwrap();

    let (digest, bytes) = sha256_file(&path).unwrap();
    assert_eq!(
        digest,
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    );
    assert_eq!(bytes, 11);
}

#[test]
fn sha256_file_streams_past_one_chunk() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("big");
    // Two full 1 MiB chunks plus a remainder, so the loop runs more than once.
    let bytes = vec![7u8; 2 * 1024 * 1024 + 3];
    std::fs::write(&path, &bytes).unwrap();

    let (_, counted) = sha256_file(&path).unwrap();
    assert_eq!(counted, u64::try_from(bytes.len()).unwrap());
}

#[test]
fn verified_sidecar_is_hidden_and_named_after_the_model() {
    let path = Path::new("/models/qwen/Qwen3.gguf");
    assert_eq!(
        verified_sidecar_path(path),
        PathBuf::from("/models/qwen/.Qwen3.gguf.pam-model.verified")
    );
}

#[test]
fn a_dense_model_scans_too() {
    let bytes = synth_gguf(
        3,
        "qwen3",
        15,
        &[("output.weight", &[8, 8], GGML_F32)],
        &[("qwen3.context_length", GgufValue::U32(8_192))],
    );
    let (_dir, registry) = models_dir_with("dense.gguf", &bytes);

    let entry = registry.find("qwen/dense").unwrap().unwrap();
    let info = entry.info.unwrap();
    assert_eq!(info.architecture, "qwen3");
    assert_eq!(info.expert_count, None);
    assert_eq!(info.context_length, Some(8_192));
}

#[test]
fn default_models_dir_is_llm_under_home() {
    let dir = default_models_dir().expect("a home directory exists in the test environment");
    assert!(dir.ends_with("llm"), "{dir:?} should end in llm");
}
