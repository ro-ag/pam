use std::{fs, path::PathBuf, time::SystemTime};

use pam_core::{ContentDigest, EvidenceHandle};
use pam_protocol::{
    EvidenceChunk, EvidenceMetadata, EvidenceRedaction, EvidenceRetention, OperationTruth,
};
use sha2::{Digest, Sha256};

use super::evidence::{
    EvidenceAssembler, EvidenceError, OutputError, OutputFinalizationStage, TemporaryOutput,
    write_new_output,
};

fn handle() -> EvidenceHandle {
    EvidenceHandle::parse("evidence://ci/1842/failure").unwrap()
}

fn digest(bytes: &[u8]) -> ContentDigest {
    ContentDigest::from_sha256(Sha256::digest(bytes).into())
}

fn metadata(bytes: &[u8]) -> EvidenceMetadata {
    EvidenceMetadata {
        handle: handle(),
        digest: digest(bytes),
        size_bytes: bytes.len() as u64,
        media_type: "application/octet-stream".to_owned(),
        retention: EvidenceRetention::Project,
        redaction: EvidenceRedaction::Unredacted,
        created_at_unix_ms: 42,
    }
}

#[test]
fn assembler_accepts_contiguous_chunks_and_verifies_size_and_digest() {
    let exact = b"exact evidence bytes";
    let mut assembler =
        EvidenceAssembler::new(handle(), metadata(exact), OperationTruth::Observed).unwrap();
    assembler
        .push(
            &EvidenceChunk::new(handle(), 0, exact[..5].to_vec(), false).unwrap(),
            OperationTruth::Observed,
        )
        .unwrap();
    assembler
        .push(
            &EvidenceChunk::new(handle(), 5, exact[5..].to_vec(), true).unwrap(),
            OperationTruth::Observed,
        )
        .unwrap();

    let download = assembler.finish().unwrap();
    assert_eq!(download.bytes, exact);
    assert_eq!(download.metadata.digest, digest(exact));
    assert_eq!(download.truth, OperationTruth::Observed);
}

#[test]
fn assembler_requires_a_terminal_eof_chunk_for_empty_evidence() {
    let mut assembler =
        EvidenceAssembler::new(handle(), metadata(&[]), OperationTruth::Verified).unwrap();
    assert!(!assembler.complete());
    assembler
        .push(
            &EvidenceChunk::new(handle(), 0, Vec::new(), true).unwrap(),
            OperationTruth::Verified,
        )
        .unwrap();
    assert!(assembler.complete());
    assert!(assembler.finish().unwrap().bytes.is_empty());
}

#[test]
fn assembler_rejects_handle_offset_eof_size_and_digest_discontinuities() {
    let exact = b"abcdef";
    let other = EvidenceHandle::parse("evidence://ci/1842/other").unwrap();

    assert!(matches!(
        EvidenceAssembler::new(other, metadata(exact), OperationTruth::Observed),
        Err(EvidenceError::HandleMismatch)
    ));

    let mut wrong_offset =
        EvidenceAssembler::new(handle(), metadata(exact), OperationTruth::Observed).unwrap();
    assert!(matches!(
        wrong_offset.push(
            &EvidenceChunk::new(handle(), 1, vec![b'a'], false).unwrap(),
            OperationTruth::Observed,
        ),
        Err(EvidenceError::OffsetMismatch { .. })
    ));

    let mut early_eof =
        EvidenceAssembler::new(handle(), metadata(exact), OperationTruth::Observed).unwrap();
    assert!(matches!(
        early_eof.push(
            &EvidenceChunk::new(handle(), 0, b"abc".to_vec(), true).unwrap(),
            OperationTruth::Observed,
        ),
        Err(EvidenceError::PrematureEof)
    ));

    let mut missing_eof =
        EvidenceAssembler::new(handle(), metadata(exact), OperationTruth::Observed).unwrap();
    assert!(matches!(
        missing_eof.push(
            &EvidenceChunk::new(handle(), 0, exact.to_vec(), false).unwrap(),
            OperationTruth::Observed,
        ),
        Err(EvidenceError::MissingEof)
    ));

    let mut wrong_digest_metadata = metadata(exact);
    wrong_digest_metadata.digest = digest(b"different");
    let mut wrong_digest =
        EvidenceAssembler::new(handle(), wrong_digest_metadata, OperationTruth::Observed).unwrap();
    wrong_digest
        .push(
            &EvidenceChunk::new(handle(), 0, exact.to_vec(), true).unwrap(),
            OperationTruth::Observed,
        )
        .unwrap();
    assert!(matches!(
        wrong_digest.finish(),
        Err(EvidenceError::DigestMismatch { .. })
    ));
}

#[test]
fn assembler_rejects_evidence_above_the_cli_buffer_limit_before_allocation() {
    let mut oversized = metadata(&[]);
    oversized.size_bytes = 64 * 1024 * 1024 + 1;

    assert!(matches!(
        EvidenceAssembler::new(handle(), oversized, OperationTruth::Observed),
        Err(EvidenceError::TooLarge { .. })
    ));
}

#[test]
fn assembler_refuses_unresolved_or_blocked_truth_and_mixed_resolved_truth() {
    for truth in [OperationTruth::Unresolved, OperationTruth::Blocked] {
        assert!(matches!(
            EvidenceAssembler::new(handle(), metadata(b"x"), truth.clone()),
            Err(EvidenceError::NonPublishableTruth {
                stage: "metadata",
                truth: actual,
            }) if actual == truth
        ));
    }

    let mut assembler =
        EvidenceAssembler::new(handle(), metadata(b"x"), OperationTruth::Observed).unwrap();
    for truth in [
        OperationTruth::Unresolved,
        OperationTruth::Blocked,
        OperationTruth::Verified,
    ] {
        let error = assembler
            .push(
                &EvidenceChunk::new(handle(), 0, b"x".to_vec(), true).unwrap(),
                truth.clone(),
            )
            .unwrap_err();
        if matches!(truth, OperationTruth::Unresolved | OperationTruth::Blocked) {
            assert!(matches!(
                error,
                EvidenceError::NonPublishableTruth {
                    stage: "chunk",
                    truth: actual,
                } if actual == truth
            ));
        } else {
            assert!(matches!(
                error,
                EvidenceError::TruthMismatch {
                    expected: OperationTruth::Observed,
                    actual: OperationTruth::Verified,
                }
            ));
        }
    }
}

#[test]
fn atomic_output_creates_exact_file_and_never_overwrites_existing_target() {
    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "pam-cli-evidence-output-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&directory).unwrap();
    let target = directory.join(PathBuf::from("evidence.bin"));

    write_new_output(&target, b"verified bytes").unwrap();
    assert_eq!(fs::read(&target).unwrap(), b"verified bytes");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert!(matches!(
        write_new_output(&target, b"replacement"),
        Err(OutputError::AlreadyExists(path)) if path == target
    ));
    assert_eq!(fs::read(&target).unwrap(), b"verified bytes");
    assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);

    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn failed_temporary_unlink_retains_the_path_for_drop_retry() {
    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "pam-cli-evidence-cleanup-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&path).unwrap();
    let mut temporary = TemporaryOutput::for_test(path.clone());

    assert!(temporary.remove().is_err());
    assert!(temporary.retains_path());

    fs::remove_dir(path).unwrap();
}

#[test]
fn post_publication_errors_report_that_the_target_was_written() {
    let error = OutputError::Published {
        path: PathBuf::from("evidence.bin"),
        stage: OutputFinalizationStage::DirectorySync,
        source: std::io::Error::other("injected sync failure"),
    };

    assert_eq!(
        error.to_string(),
        "evidence was written to evidence.bin, but PAM could not confirm directory durability"
    );
    assert_eq!(
        std::error::Error::source(&error).unwrap().to_string(),
        "injected sync failure"
    );
}
