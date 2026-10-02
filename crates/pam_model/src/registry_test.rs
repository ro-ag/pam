use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::engine::Target;
use crate::engine_server::{EngineContract, ServerOptions};
use crate::gguf_test::{GGML_F32, GgufValue, synth_gguf, tiny_moe_gguf};
use crate::qualification::Qualification;
use crate::registry::{
    ModelClass, ModelEntry, Registry, RegistryError, VerifiedRecord, classify, default_models_dir,
    is_plain_name, qualify, sha256_file, verified_sidecar_path,
};
use crate::weights::{CopyHooks, CopyMethod, FREE_SPACE_HEADROOM_BYTES, WeightsError};

/// A models dir with `qwen/<name>` written from `bytes`.
fn models_dir_with(name: &str, bytes: &[u8]) -> (tempfile::TempDir, Registry) {
    let dir = tempfile::tempdir().unwrap();
    let vendor = dir.path().join("qwen");
    std::fs::create_dir_all(&vendor).unwrap();
    std::fs::write(vendor.join(name), bytes).unwrap();
    let registry = private(Registry::new(dir.path()), &dir);
    (dir, registry)
}

/// `registry` with the private stores a daemon gives it.
fn private(registry: Registry, models: &tempfile::TempDir) -> Registry {
    registry
        .with_trust_dir(trust_dir(models))
        .with_weights_dir(weights_dir(models))
}

/// The private trust directory a test registry keeps its records in: a dot
/// directory beside the vendors, which a scan skips.
fn trust_dir(models: &tempfile::TempDir) -> PathBuf {
    models.path().join(".private-trust")
}

/// The private weights directory of a test registry, also skipped by a scan.
fn weights_dir(models: &tempfile::TempDir) -> PathBuf {
    models.path().join(".private-weights")
}

/// The files in the private weights directory.
fn private_copies(models: &tempfile::TempDir) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(weights_dir(models)).map_or_else(
        |_| Vec::new(),
        |entries| {
            entries
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect()
        },
    );
    names.sort();
    names
}

/// The engine options this build starts the model at `path` with (its header decides
/// the context).
fn engine_for(path: &Path) -> EngineContract {
    let context = crate::gguf::read_info(path)
        .ok()
        .and_then(|info| info.context_length);
    EngineContract::of(&ServerOptions::for_model(context))
}

/// Hooks that behave like another volume: nothing clones, `free` bytes are free.
fn other_volume(free: Option<u64>) -> CopyHooks {
    CopyHooks {
        clone: Arc::new(|_, _| Ok(false)),
        free_bytes: Arc::new(move |_| free),
    }
}

/// How many verification records the trust directory holds.
fn trust_record_count(registry: &Registry) -> usize {
    std::fs::read_dir(registry.trust_dir().unwrap()).map_or(0, Iterator::count)
}

/// A legacy sidecar claiming `sha256` for a file of `size`, written the way pam
/// used to (newer than the file, correct size).
fn forge_sidecar(path: &Path, sha256: &str, size: u64) {
    let record = VerifiedRecord {
        sha256: sha256.to_owned(),
        size_bytes: size,
        verified_ts: 1,
        matches_catalog: None,
    };
    std::fs::write(
        verified_sidecar_path(path),
        serde_json::to_vec(&record).unwrap(),
    )
    .unwrap();
}

#[test]
fn classify_admits_only_a_verified_digest() {
    let record = VerifiedRecord {
        sha256: "a".repeat(64),
        size_bytes: 1,
        verified_ts: 0,
        matches_catalog: None,
    };
    assert_eq!(classify(Some(&record)), ModelClass::Engine);
    assert_eq!(classify(None), ModelClass::TestOnly);
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
fn verify_records_in_the_private_store_and_the_next_scan_reads_it_back() {
    let (_dir, registry) = models_dir_with("tiny.gguf", &tiny_moe_gguf());
    let entry = registry.find("qwen/tiny").unwrap().unwrap();

    let outcome = registry.verify(&entry).unwrap();
    assert_eq!(outcome.size_bytes, entry.size_bytes);
    assert_eq!(outcome.sha256.len(), 64);
    assert_eq!(outcome.matches_catalog, None);
    assert!(
        !verified_sidecar_path(&entry.path).exists(),
        "nothing is written beside the file, where the models directory's writers could forge it"
    );
    assert_eq!(trust_record_count(&registry), 1);

    let rescanned = registry.find("qwen/tiny").unwrap().unwrap();
    assert_eq!(rescanned.class, ModelClass::Engine);
    assert_eq!(rescanned.verification_issue, None);
    let record = rescanned.verified.expect("the record is read back");
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
        "and the verdict survives the record round trip"
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
    let (dir, registry) = models_dir_with("tiny.gguf", &tiny_moe_gguf());
    let entry = registry.find("qwen/tiny").unwrap().unwrap();
    let (sha256, _) = sha256_file(&entry.path).unwrap();

    let record = VerifiedRecord {
        sha256: sha256.clone(),
        size_bytes: entry.size_bytes,
        verified_ts: 1_700_000_000,
        matches_catalog: Some(true),
    };
    registry.record_verified(&entry.path, &record).unwrap();

    let rescanned = registry.find("qwen/tiny").unwrap().unwrap();
    assert_eq!(rescanned.verified, Some(record));
    assert_eq!(
        private_copies(&dir),
        vec![format!("{sha256}.gguf")],
        "a download is materialised like any verification"
    );
}

/// The digest a download reports was computed over a file in the models directory;
/// the record is only written when PAM's own copy of the file has that digest.
#[test]
fn a_download_record_whose_digest_is_not_the_files_is_refused() {
    let (dir, registry) = models_dir_with("tiny.gguf", &tiny_moe_gguf());
    let entry = registry.find("qwen/tiny").unwrap().unwrap();

    let refused = registry
        .record_download(&entry.path, &"a".repeat(64), entry.size_bytes)
        .unwrap_err();
    assert!(
        matches!(&refused, RegistryError::DigestMismatch { expected, .. } if *expected == "a".repeat(64)),
        "{refused:?}"
    );
    assert!(refused.to_string().contains("Verify"), "{refused}");
    assert_eq!(trust_record_count(&registry), 0);
    assert!(private_copies(&dir).is_empty(), "no copy is kept either");
    assert_eq!(
        registry.find("qwen/tiny").unwrap().unwrap().class,
        ModelClass::TestOnly
    );
}

#[test]
fn an_unreadable_trust_record_is_ignored_rather_than_fatal() {
    let (_dir, registry) = models_dir_with("tiny.gguf", &tiny_moe_gguf());
    let entry = registry.find("qwen/tiny").unwrap().unwrap();
    registry.verify(&entry).unwrap();
    for record in std::fs::read_dir(registry.trust_dir().unwrap()).unwrap() {
        std::fs::write(record.unwrap().path(), b"{ not json").unwrap();
    }

    let rescanned = registry.find("qwen/tiny").unwrap().unwrap();
    assert_eq!(rescanned.verified, None);
    assert!(
        rescanned
            .verification_issue
            .unwrap()
            .contains("verify again")
    );
}

#[test]
fn delete_removes_the_model_its_trust_record_and_a_legacy_sidecar() {
    let (_dir, registry) = models_dir_with("tiny.gguf", &tiny_moe_gguf());
    let entry = registry.find("qwen/tiny").unwrap().unwrap();
    registry.verify(&entry).unwrap();
    forge_sidecar(&entry.path, &"a".repeat(64), entry.size_bytes);
    let sidecar = verified_sidecar_path(&entry.path);
    assert!(sidecar.exists());
    assert_eq!(trust_record_count(&registry), 1);

    registry.delete(&entry).unwrap();
    assert!(!entry.path.exists());
    assert!(!sidecar.exists());
    assert_eq!(trust_record_count(&registry), 0);
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
        verification_issue: None,
        fingerprint: crate::registry::FileFingerprint::default(),
        private_copy: None,
        qualification: None,
        qualification_issue: None,
        catalog_id: None,
    }
}

/// Leaks a one-record table naming `sha256` on the current target, measured with the
/// engine options this build starts the tiny fixture model with, the way a harness
/// qualifies a fixture it just hashed.
fn table_for(sha256: &str) -> &'static [Qualification] {
    let dir = tempfile::tempdir().unwrap();
    let model = dir.path().join("tiny.gguf");
    std::fs::write(&model, tiny_moe_gguf()).unwrap();
    table_measured_with(sha256, engine_for(&model))
}

/// [`table_for`] with the engine options the record was measured with supplied.
fn table_measured_with(sha256: &str, engine: EngineContract) -> &'static [Qualification] {
    let record = fixture_record(sha256, engine);
    let fingerprint = record.bench().fingerprint(&record.engine);
    Box::leak(
        vec![Qualification {
            bench_contract: Box::leak(fingerprint.into_boxed_str()),
            ..record
        }]
        .into_boxed_slice(),
    )
}

fn fixture_record(sha256: &str, engine: EngineContract) -> Qualification {
    Qualification {
        artifact: "fixture",
        sha256: Box::leak(sha256.to_owned().into_boxed_str()),
        engine_tag: crate::engine::ENGINE_TAG,
        targets: Box::leak(vec![Target::current().unwrap()].into_boxed_slice()),
        contract: "test",
        case_set_sha256: "",
        record: "docs/benchmarks/none",
        host: "test",
        accuracy: 1.0,
        false_passes: 0,
        warm_p95_ms: 1,
        decided: "2026-01-01",
        system_sha256: "",
        output_cap: 160,
        input_limit: 640,
        engine,
        bench_contract: "",
    }
}

#[test]
fn a_verified_digest_is_qualified_only_when_a_record_names_it_on_this_target() {
    let (dir, _) = models_dir_with("tiny.gguf", &tiny_moe_gguf());
    let path = dir.path().join("qwen").join("tiny.gguf");
    let (sha256, size) = sha256_file(&path).unwrap();

    let unqualified = private(
        Registry::with_qualifications(dir.path(), table_for("not-this-digest")),
        &dir,
    );
    unqualified
        .record_verified(
            &path,
            &VerifiedRecord {
                sha256: sha256.clone(),
                size_bytes: size,
                verified_ts: 0,
                matches_catalog: None,
            },
        )
        .unwrap();
    let entry = unqualified.find("qwen/tiny").unwrap().unwrap();
    assert_eq!(entry.class, ModelClass::Engine, "verified");
    assert_eq!(
        entry.qualification, None,
        "but nothing measured this digest"
    );
    assert_eq!(
        entry.qualification_issue, None,
        "and no record means there is nothing to re-measure"
    );

    let qualified = private(
        Registry::with_qualifications(dir.path(), table_for(&sha256)),
        &dir,
    );
    let entry = qualified.find("qwen/tiny").unwrap().unwrap();
    assert_eq!(
        entry.qualification.map(|record| record.artifact),
        Some("fixture")
    );
    assert_eq!(entry.qualification_issue, None);

    assert_eq!(
        qualify(None, table_for(&sha256), &engine_for(&path)),
        (None, None),
        "an unverified file is never qualified, whatever the table says"
    );
}

/// The badge is bound to what the bench measured: the same digest, engine tag and target
/// stop qualifying the moment this build starts the model with an option the record was
/// not measured with, and the entry says which.
#[test]
fn a_record_measured_with_other_engine_options_does_not_qualify() {
    let (dir, registry) = models_dir_with("tiny.gguf", &tiny_moe_gguf());
    let path = dir.path().join("qwen").join("tiny.gguf");
    let entry = registry.find("qwen/tiny").unwrap().unwrap();
    let sha256 = registry.verify(&entry).unwrap().sha256;
    let measured = private(
        Registry::with_qualifications(dir.path(), table_for(&sha256)),
        &dir,
    );
    assert!(
        measured
            .find("qwen/tiny")
            .unwrap()
            .unwrap()
            .qualification
            .is_some(),
        "qualified with the options it was measured with"
    );

    // The same record, measured when the supervisor sent another seed.
    let reseeded = EngineContract {
        seed: 9,
        ..engine_for(&path)
    };
    let other = private(
        Registry::with_qualifications(dir.path(), table_measured_with(&sha256, reseeded)),
        &dir,
    );
    let entry = other.find("qwen/tiny").unwrap().unwrap();
    assert_eq!(entry.class, ModelClass::Engine, "still verified");
    assert_eq!(entry.qualification, None, "the badge is not carried over");
    let issue = entry.qualification_issue.expect("and the entry says why");
    assert!(
        issue.contains("seed: measured 9, now 7")
            && issue.contains("re-measurement")
            && issue.contains("docs/benchmarks/none"),
        "{issue}"
    );
}

/// The engine options are per model: one whose header lowers the context is started
/// below the envelope, so a record measured at the envelope does not describe it.
#[test]
fn a_model_started_below_the_measured_context_is_not_covered_by_the_record() {
    let small = synth_gguf(
        3,
        "qwen3",
        15,
        &[("output.weight", &[8, 8], GGML_F32)],
        &[("qwen3.context_length", GgufValue::U32(4_096))],
    );
    let (dir, registry) = models_dir_with("small.gguf", &small);
    let entry = registry.find("qwen/small").unwrap().unwrap();
    let sha256 = registry.verify(&entry).unwrap().sha256;
    let at_envelope = EngineContract::of(&ServerOptions::default());
    let table = table_measured_with(&sha256, at_envelope);

    let entry = private(Registry::with_qualifications(dir.path(), table), &dir)
        .find("qwen/small")
        .unwrap()
        .unwrap();
    assert_eq!(entry.qualification, None);
    assert!(
        entry
            .qualification_issue
            .unwrap()
            .contains("context_tokens: measured 8192, now 4096")
    );
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

#[test]
fn checked_dest_for_refuses_anything_but_one_plain_segment() {
    let registry = Registry::new("/models");
    assert_eq!(
        registry.checked_dest_for("qwen", "Qwen3.gguf").unwrap(),
        PathBuf::from("/models").join("qwen").join("Qwen3.gguf")
    );
    for bad in [
        "",
        ".",
        "..",
        "../x",
        "..\\x",
        "a/b",
        "a\\b",
        "/tmp",
        "C:\\x",
        ".hidden",
        "a b",
        "a\0b",
        "ünïcode",
    ] {
        assert!(!is_plain_name(bad), "{bad:?} must not be a plain name");
        assert!(
            matches!(
                registry.checked_dest_for(bad, "Qwen3.gguf"),
                Err(RegistryError::InvalidName(name)) if name == bad
            ),
            "vendor {bad:?} must be refused"
        );
        assert!(
            matches!(
                registry.checked_dest_for("qwen", bad),
                Err(RegistryError::InvalidName(name)) if name == bad
            ),
            "file name {bad:?} must be refused"
        );
    }
    for good in ["qwen", "gpt-oss_20b.v2", "A1"] {
        assert!(is_plain_name(good), "{good}");
    }
}

#[test]
fn a_rewritten_model_file_loses_its_verification_and_qualification() {
    let (dir, _) = models_dir_with("tiny.gguf", &tiny_moe_gguf());
    let path = dir.path().join("qwen").join("tiny.gguf");
    let (sha256, size) = sha256_file(&path).unwrap();
    let registry = private(
        Registry::with_qualifications(dir.path(), table_for(&sha256)),
        &dir,
    );
    registry
        .record_verified(
            &path,
            &VerifiedRecord {
                sha256,
                size_bytes: size,
                verified_ts: 0,
                matches_catalog: None,
            },
        )
        .unwrap();
    let entry = registry.find("qwen/tiny").unwrap().unwrap();
    assert_eq!(entry.class, ModelClass::Engine);
    assert!(
        entry.qualification.is_some(),
        "the fixture is qualified before the rewrite"
    );

    // Another file lands under the verified name: one more tensor, so the
    // size differs and the old record no longer describes these bytes.
    let rewritten = synth_gguf(
        3,
        "qwen3",
        15,
        &[("output.weight", &[8, 8], GGML_F32)],
        &[("qwen3.context_length", GgufValue::U32(8_192))],
    );
    assert_ne!(rewritten.len(), tiny_moe_gguf().len());
    std::fs::write(&path, &rewritten).unwrap();

    let entry = registry.find("qwen/tiny").unwrap().unwrap();
    assert_eq!(entry.verified, None, "a record for other bytes is absent");
    assert_eq!(entry.class, ModelClass::TestOnly);
    assert_eq!(entry.qualification, None);
    assert!(
        entry.verification_issue.unwrap().contains("changed"),
        "the human is told the file changed, not just that it is unverified"
    );
    assert_eq!(
        trust_record_count(&registry),
        1,
        "nothing is deleted, only distrusted"
    );
}

/// An in-place edit that keeps the size and puts the modification time back is
/// what a sidecar's mtime comparison could not see; the change time cannot be set
/// back by a writer.
#[cfg(unix)]
#[test]
fn a_same_size_edit_with_the_old_mtime_restored_still_loses_verification() {
    let (dir, registry) = models_dir_with("tiny.gguf", &tiny_moe_gguf());
    let path = dir.path().join("qwen").join("tiny.gguf");
    let entry = registry.find("qwen/tiny").unwrap().unwrap();
    registry.verify(&entry).unwrap();
    let verified = registry.find("qwen/tiny").unwrap().unwrap();
    assert!(verified.verified.is_some());

    let old_mtime = std::fs::metadata(&path).unwrap().modified().unwrap();
    let mut bytes = tiny_moe_gguf();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    std::thread::sleep(std::time::Duration::from_millis(20));
    std::fs::write(&path, &bytes).unwrap();
    std::fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(old_mtime)
        .unwrap();

    let after = registry.find("qwen/tiny").unwrap().unwrap();
    assert_eq!(after.verified, None, "the digest describes other bytes");
    assert_eq!(after.class, ModelClass::TestOnly);
    assert_eq!(
        after.engine_path(),
        path,
        "an unverified entry has no private copy to load"
    );
    // A load that began from the verified scan is unaffected: it never opens the file
    // that was edited, and what it does open still has the verified digest.
    registry.recheck(&verified).unwrap();
    assert_eq!(
        sha256_file(verified.engine_path()).unwrap().0,
        verified.verified.unwrap().sha256
    );
}

#[test]
fn a_forged_sidecar_in_the_models_directory_confers_nothing() {
    let (dir, registry) = models_dir_with("tiny.gguf", &tiny_moe_gguf());
    let path = dir.path().join("qwen").join("tiny.gguf");
    let (sha256, size) = sha256_file(&path).unwrap();
    // The attacker names the qualified digest and gets the size and the mtime right.
    forge_sidecar(&path, &sha256, size);
    let qualified = private(
        Registry::with_qualifications(dir.path(), table_for(&sha256)),
        &dir,
    );

    let entry = qualified.find("qwen/tiny").unwrap().unwrap();
    assert_eq!(entry.verified, None);
    assert_eq!(entry.class, ModelClass::TestOnly);
    assert_eq!(
        entry.qualification, None,
        "no qualification without a verification"
    );
    let issue = entry.verification_issue.expect("the human is told why");
    assert!(
        issue.contains("sidecar") && issue.contains("verify again"),
        "{issue}"
    );
    assert_eq!(trust_record_count(&registry), 0);
    // And with no trust directory at all, nothing is verified either.
    let bare = Registry::with_qualifications(dir.path(), table_for(&sha256));
    assert_eq!(
        bare.find("qwen/tiny").unwrap().unwrap().class,
        ModelClass::TestOnly
    );
}

#[test]
fn an_install_with_only_old_sidecars_degrades_to_verify_again_and_recovers() {
    let (dir, registry) = models_dir_with("tiny.gguf", &tiny_moe_gguf());
    let path = dir.path().join("qwen").join("tiny.gguf");
    let (sha256, size) = sha256_file(&path).unwrap();
    forge_sidecar(&path, &sha256, size);

    let before = registry.find("qwen/tiny").unwrap().unwrap();
    assert_eq!(before.class, ModelClass::TestOnly);
    assert!(before.verification_issue.is_some());

    registry.verify(&before).unwrap();
    let after = registry.find("qwen/tiny").unwrap().unwrap();
    assert_eq!(after.class, ModelClass::Engine);
    assert_eq!(after.verified.as_ref().unwrap().sha256, sha256);
    assert_eq!(
        after.verification_issue, None,
        "the hint goes away once verified"
    );
    registry
        .recheck(&after)
        .expect("an unchanged file passes the load check");
}

#[test]
fn a_registry_without_a_trust_directory_refuses_to_record() {
    let (dir, _) = models_dir_with("tiny.gguf", &tiny_moe_gguf());
    let bare = Registry::new(dir.path());
    let entry = bare.find("qwen/tiny").unwrap().unwrap();

    assert!(matches!(bare.verify(&entry), Err(RegistryError::Io(_))));
    assert!(
        !verified_sidecar_path(&entry.path).exists(),
        "it never falls back to writing beside the file"
    );
}

#[test]
fn a_trust_record_copied_under_another_files_name_verifies_nothing() {
    let (dir, registry) = models_dir_with("tiny.gguf", &tiny_moe_gguf());
    let other = dir.path().join("qwen").join("other.gguf");
    std::fs::copy(dir.path().join("qwen").join("tiny.gguf"), &other).unwrap();
    let tiny = registry.find("qwen/tiny").unwrap().unwrap();
    registry.verify(&tiny).unwrap();

    // The record for `tiny` is moved to the file name `other` would look up.
    let canonical_other = other.canonicalize().unwrap();
    let digest = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
        canonical_other.to_string_lossy().as_bytes(),
    ));
    let source = std::fs::read_dir(registry.trust_dir().unwrap())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    std::fs::copy(
        &source,
        registry.trust_dir().unwrap().join(format!("{digest}.json")),
    )
    .unwrap();

    let entry = registry.find("qwen/other").unwrap().unwrap();
    assert_eq!(entry.verified, None);
    assert!(
        entry
            .verification_issue
            .unwrap()
            .contains("does not describe")
    );
}

#[test]
fn an_unchanged_file_is_not_reparsed_on_every_scan_and_an_edited_one_is() {
    let (dir, registry) = models_dir_with("tiny.gguf", &tiny_moe_gguf());
    let path = dir.path().join("qwen").join("tiny.gguf");
    let parses = || crate::registry::HEADER_PARSES.with(std::cell::Cell::get);
    let before = parses();

    let first = registry.find("qwen/tiny").unwrap().unwrap();
    assert_eq!(parses(), before + 1, "the first scan parses the header");
    for _ in 0..3 {
        let again = registry.find("qwen/tiny").unwrap().unwrap();
        assert_eq!(again.info, first.info);
    }
    assert_eq!(parses(), before + 1, "later scans reuse it");

    // A file that stops being a model is parsed afresh, not served from the cache.
    std::fs::write(&path, b"not a gguf any more").unwrap();
    let broken = registry.find("qwen/tiny").unwrap().unwrap();
    assert_eq!(parses(), before + 2);
    assert!(broken.info.is_none() && broken.info_error.is_some());
}

/// The gap this closes: the digest used to be checked on the file in the models
/// directory, which the engine then opened by path. Now the engine is pointed at PAM's
/// own copy, so whatever happens to the models directory after the verification, a
/// verified entry loads the verified bytes.
#[test]
fn a_source_swapped_after_verification_does_not_change_what_the_engine_loads() {
    let (dir, registry) = models_dir_with("tiny.gguf", &tiny_moe_gguf());
    let path = dir.path().join("qwen").join("tiny.gguf");
    let entry = registry.find("qwen/tiny").unwrap().unwrap();
    assert_eq!(entry.engine_path(), path, "unverified: the file itself");
    let outcome = registry.verify(&entry).unwrap();

    let verified = registry.find("qwen/tiny").unwrap().unwrap();
    let load_path = verified.engine_path().to_path_buf();
    assert_eq!(
        load_path,
        weights_dir(&dir).join(format!("{}.gguf", outcome.sha256)),
        "a verified entry loads the private copy, named by its digest"
    );
    assert_ne!(load_path, path);

    // The swap the fingerprint re-check could only narrow: an atomic rename of other
    // bytes (same length) over the verified name, after the scan the load is based on.
    let mut evil = tiny_moe_gguf();
    let last = evil.len() - 1;
    evil[last] ^= 0xff;
    // Off Unix the fingerprint is size and mtime only, and NTFS stamps a write with a
    // coarse clock tick: without a pause the swap can land in the tick the original was
    // written in and be indistinguishable by design (see `FileFingerprint`).
    std::thread::sleep(std::time::Duration::from_millis(50));
    let staged = dir.path().join("qwen").join(".evil");
    std::fs::write(&staged, &evil).unwrap();
    std::fs::rename(&staged, &path).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), evil);

    registry
        .recheck(&verified)
        .expect("the load check is about the private copy, which nothing touched");
    assert_eq!(
        std::fs::read(&load_path).unwrap(),
        tiny_moe_gguf(),
        "the engine is given the verified bytes"
    );
    assert_eq!(sha256_file(&load_path).unwrap().0, outcome.sha256);

    // And the models directory's file is no longer called verified.
    let rescanned = registry.find("qwen/tiny").unwrap().unwrap();
    assert_eq!(rescanned.class, ModelClass::TestOnly);
    assert_eq!(rescanned.private_copy, None);
}

#[test]
fn the_private_copy_is_what_the_load_check_guards() {
    let (dir, registry) = models_dir_with("tiny.gguf", &tiny_moe_gguf());
    let entry = registry.find("qwen/tiny").unwrap().unwrap();
    registry.verify(&entry).unwrap();
    let verified = registry.find("qwen/tiny").unwrap().unwrap();
    let private_path = verified.engine_path().to_path_buf();

    // Someone with access to the private base replaces the copy.
    std::fs::remove_file(&private_path).unwrap();
    std::fs::write(&private_path, b"other bytes").unwrap();
    let refused = registry.recheck(&verified).unwrap_err();
    assert!(
        matches!(&refused, RegistryError::Changed { what, .. } if what.contains("private copy")),
        "{refused:?}"
    );
    let rescanned = registry.find("qwen/tiny").unwrap().unwrap();
    assert_eq!(rescanned.class, ModelClass::TestOnly);
    let issue = rescanned.verification_issue.unwrap();
    assert!(
        issue.contains("private copy") && issue.contains("verify again"),
        "{issue}"
    );

    // Gone altogether (the base was cleaned by hand): the same, with its own words.
    std::fs::remove_file(&private_path).unwrap();
    assert!(matches!(
        registry.recheck(&verified),
        Err(RegistryError::Changed { .. })
    ));
    let issue = registry
        .find("qwen/tiny")
        .unwrap()
        .unwrap()
        .verification_issue
        .unwrap();
    assert!(issue.contains("is missing"), "{issue}");

    // One Verify recovers.
    registry.verify(&entry).unwrap();
    assert_eq!(
        registry.find("qwen/tiny").unwrap().unwrap().class,
        ModelClass::Engine
    );
    assert_eq!(private_copies(&dir).len(), 1);
}

#[test]
fn delete_removes_the_private_copy_unless_another_verified_file_shares_it() {
    let (dir, registry) = models_dir_with("tiny.gguf", &tiny_moe_gguf());
    let twin = dir.path().join("qwen").join("twin.gguf");
    std::fs::write(&twin, tiny_moe_gguf()).unwrap();
    let tiny = registry.find("qwen/tiny").unwrap().unwrap();
    let first = registry.verify(&tiny).unwrap();
    let twin_entry = registry.find("qwen/twin").unwrap().unwrap();
    let second = registry.verify(&twin_entry).unwrap();
    assert_eq!(first.sha256, second.sha256);
    assert_eq!(
        second.private_copy,
        CopyMethod::Reused,
        "the same bytes are kept once"
    );
    assert_eq!(private_copies(&dir), vec![format!("{}.gguf", first.sha256)]);
    assert_eq!(
        registry.find("qwen/tiny").unwrap().unwrap().class,
        ModelClass::Engine,
        "verifying the twin did not invalidate the first record"
    );

    registry.delete(&tiny).unwrap();
    assert_eq!(
        private_copies(&dir).len(),
        1,
        "the twin still needs the copy"
    );
    assert_eq!(
        registry.find("qwen/twin").unwrap().unwrap().class,
        ModelClass::Engine
    );

    registry.delete(&twin_entry).unwrap();
    assert!(
        private_copies(&dir).is_empty(),
        "the last model with these bytes takes the private copy with it"
    );
    assert_eq!(trust_record_count(&registry), 0);
}

#[test]
fn a_verification_with_a_new_digest_replaces_the_old_private_copy() {
    let (dir, registry) = models_dir_with("tiny.gguf", &tiny_moe_gguf());
    let path = dir.path().join("qwen").join("tiny.gguf");
    let entry = registry.find("qwen/tiny").unwrap().unwrap();
    let old = registry.verify(&entry).unwrap();

    let mut newer = tiny_moe_gguf();
    let last = newer.len() - 1;
    newer[last] ^= 0xff;
    std::fs::write(&path, &newer).unwrap();
    let entry = registry.find("qwen/tiny").unwrap().unwrap();
    let new = registry.verify(&entry).unwrap();

    assert_ne!(old.sha256, new.sha256);
    assert_eq!(
        private_copies(&dir),
        vec![format!("{}.gguf", new.sha256)],
        "one copy per live verification"
    );
    assert_eq!(trust_record_count(&registry), 1);
}

#[test]
fn another_volume_falls_back_to_a_hashed_copy() {
    let (dir, _) = models_dir_with("tiny.gguf", &tiny_moe_gguf());
    let registry = Registry::new(dir.path())
        .with_trust_dir(trust_dir(&dir))
        .with_weights_store(weights_dir(&dir), other_volume(None));
    let entry = registry.find("qwen/tiny").unwrap().unwrap();
    let (expected, _) = sha256_file(&entry.path).unwrap();

    let reported = std::sync::atomic::AtomicU64::new(0);
    let control = crate::weights::Control {
        progress: &|done| reported.store(done, std::sync::atomic::Ordering::SeqCst),
        cancelled: &|| false,
    };
    let outcome = registry.verify_with(&entry, &control).unwrap();
    assert_eq!(outcome.private_copy, CopyMethod::Copied);
    assert_eq!(outcome.sha256, expected);
    assert_eq!(
        reported.load(std::sync::atomic::Ordering::SeqCst),
        entry.size_bytes,
        "the job sees the copy advance"
    );

    let verified = registry.find("qwen/tiny").unwrap().unwrap();
    assert_eq!(verified.class, ModelClass::Engine);
    assert_eq!(
        std::fs::read(verified.engine_path()).unwrap(),
        tiny_moe_gguf()
    );
}

#[test]
fn a_short_disk_refuses_the_verification_with_the_bytes_needed() {
    let (dir, _) = models_dir_with("tiny.gguf", &tiny_moe_gguf());
    let registry = Registry::new(dir.path())
        .with_trust_dir(trust_dir(&dir))
        .with_weights_store(weights_dir(&dir), other_volume(Some(512)));
    let entry = registry.find("qwen/tiny").unwrap().unwrap();

    let refused = registry.verify(&entry).unwrap_err();
    let needed = entry.size_bytes + FREE_SPACE_HEADROOM_BYTES;
    assert!(
        matches!(
            &refused,
            RegistryError::Weights(WeightsError::NoSpace { needed: n, free: Some(512), .. }) if *n == needed
        ),
        "{refused:?}"
    );
    let message = refused.to_string();
    assert!(
        message.contains(&format!("{needed} bytes needed")) && message.contains("512 bytes free"),
        "{message}"
    );
    assert_eq!(trust_record_count(&registry), 0, "nothing is recorded");
    assert!(
        private_copies(&dir).is_empty(),
        "and nothing is left behind"
    );
    assert_eq!(
        registry.find("qwen/tiny").unwrap().unwrap().class,
        ModelClass::TestOnly
    );
}

#[test]
fn a_cancelled_verification_leaves_no_copy_and_no_record() {
    let (dir, _) = models_dir_with("tiny.gguf", &tiny_moe_gguf());
    let registry = Registry::new(dir.path())
        .with_trust_dir(trust_dir(&dir))
        .with_weights_store(weights_dir(&dir), other_volume(None));
    let entry = registry.find("qwen/tiny").unwrap().unwrap();

    let control = crate::weights::Control {
        progress: &|_| {},
        cancelled: &|| true,
    };
    assert!(matches!(
        registry.verify_with(&entry, &control),
        Err(RegistryError::Weights(WeightsError::Cancelled))
    ));
    assert_eq!(trust_record_count(&registry), 0);
    assert!(private_copies(&dir).is_empty());
}

#[test]
fn a_record_from_before_private_copies_asks_for_a_second_verification() {
    let (dir, registry) = models_dir_with("tiny.gguf", &tiny_moe_gguf());
    let entry = registry.find("qwen/tiny").unwrap().unwrap();
    registry.verify(&entry).unwrap();
    // Rewrite the record the way the previous layout wrote it: version 1, no private
    // copy. Its digest and fingerprint are right; it still verifies nothing.
    let record_path = std::fs::read_dir(registry.trust_dir().unwrap())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&record_path).unwrap()).unwrap();
    record["version"] = 1.into();
    record
        .as_object_mut()
        .unwrap()
        .remove("private_fingerprint");
    std::fs::write(&record_path, serde_json::to_vec(&record).unwrap()).unwrap();

    let old = registry.find("qwen/tiny").unwrap().unwrap();
    assert_eq!(old.class, ModelClass::TestOnly);
    assert_eq!(old.engine_path(), entry.path);
    let issue = old.verification_issue.unwrap();
    assert!(
        issue.contains("predates") && issue.contains("verify again"),
        "{issue}"
    );
    assert_eq!(private_copies(&dir).len(), 1);
}

#[test]
fn a_sweep_removes_copies_whose_source_changed_or_was_deleted_by_hand() {
    let (dir, registry) = models_dir_with("tiny.gguf", &tiny_moe_gguf());
    let path = dir.path().join("qwen").join("tiny.gguf");
    let entry = registry.find("qwen/tiny").unwrap().unwrap();
    registry.verify(&entry).unwrap();
    assert!(
        registry.sweep_private_copies(true).removed.is_empty(),
        "a live verification keeps its copy"
    );

    // The file changed and nobody verified it again: the copy backs nothing. The record
    // stays, so the listing can still say "changed, verify again".
    std::fs::write(&path, b"another model entirely").unwrap();
    let swept = registry.sweep_private_copies(false);
    assert_eq!(swept.removed.len(), 1);
    assert_eq!(swept.records_removed, 0);
    assert!(private_copies(&dir).is_empty());
    assert_eq!(trust_record_count(&registry), 1);

    // Deleted in the file manager: copy and record both go.
    let entry = registry.find("qwen/tiny").unwrap().unwrap();
    registry.verify(&entry).unwrap();
    std::fs::remove_file(&path).unwrap();
    let swept = registry.sweep_private_copies(false);
    assert_eq!((swept.removed.len(), swept.records_removed), (1, 1));
    assert!(private_copies(&dir).is_empty());
    assert_eq!(trust_record_count(&registry), 0);
}

#[test]
fn a_sweep_keeps_the_copy_of_a_model_whose_volume_is_not_mounted() {
    let models = tempfile::tempdir().unwrap();
    let private_base = tempfile::tempdir().unwrap();
    let vendor = models.path().join("external").join("qwen");
    std::fs::create_dir_all(&vendor).unwrap();
    std::fs::write(vendor.join("tiny.gguf"), tiny_moe_gguf()).unwrap();
    let registry = Registry::new(models.path().join("external"))
        .with_trust_dir(private_base.path().join("model-trust"))
        .with_weights_dir(private_base.path().join("weights"));
    let entry = registry.find("qwen/tiny").unwrap().unwrap();
    registry.verify(&entry).unwrap();

    // The whole directory tree is gone, as when a disk is unplugged: absence of the
    // file proves nothing, and the copy may have cost a full 12 GB to make.
    let parked = models.path().join("unplugged");
    std::fs::rename(models.path().join("external"), &parked).unwrap();
    let swept = registry.sweep_private_copies(false);
    assert_eq!(swept, crate::registry::SweepReport::default());
    assert_eq!(trust_record_count(&registry), 1);

    std::fs::rename(&parked, models.path().join("external")).unwrap();
    assert_eq!(
        registry.find("qwen/tiny").unwrap().unwrap().class,
        ModelClass::Engine,
        "plugged back in, it is still verified"
    );
}

#[test]
fn only_a_boot_sweep_removes_unfinished_copies() {
    let (dir, registry) = models_dir_with("tiny.gguf", &tiny_moe_gguf());
    let entry = registry.find("qwen/tiny").unwrap().unwrap();
    registry.verify(&entry).unwrap();
    // What a daemon killed mid-verification leaves.
    let leftover = weights_dir(&dir).join(".incoming-1-00000000deadbeef.part");
    std::fs::write(&leftover, b"half a model").unwrap();

    assert!(registry.sweep_private_copies(false).removed.is_empty());
    assert!(
        leftover.exists(),
        "a verification may be writing it right now"
    );
    assert_eq!(
        registry.sweep_private_copies(true).removed,
        vec![leftover.clone()]
    );
    assert_eq!(private_copies(&dir).len(), 1, "the finished copy stays");
}

#[test]
fn a_registry_without_a_private_weights_directory_verifies_nothing() {
    let (dir, _) = models_dir_with("tiny.gguf", &tiny_moe_gguf());
    let no_weights = Registry::new(dir.path()).with_trust_dir(trust_dir(&dir));
    let entry = no_weights.find("qwen/tiny").unwrap().unwrap();
    assert!(matches!(
        no_weights.verify(&entry),
        Err(RegistryError::Io(_))
    ));
    assert_eq!(trust_record_count(&no_weights), 0);
}
