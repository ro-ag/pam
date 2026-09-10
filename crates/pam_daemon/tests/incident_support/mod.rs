//! Frozen synthetic inputs and gold labels stay separate from model input.
use pam_compact::{Compacted, FragmentKind, sha256_hex};
use serde::Deserialize;
use serde_json::{Value, json};
use std::fmt::Write as _;
use std::{collections::BTreeSet, io::Read, path::Path};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema_version: u8,
    pub corpus_id: String,
    pub purpose: String,
    pub entries: Vec<Entry>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub case_id: String,
    pub case_sha256: String,
    pub source_sha256: String,
    pub source_bytes: usize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Incident {
    pub schema_version: u8,
    pub case_id: String,
    pub family_id: String,
    pub split: String,
    pub stage: String,
    pub products: Vec<String>,
    pub authenticity: String,
    pub source_reference: Value,
    pub export_policy: String,
    pub task: String,
    pub target: Value,
    pub mode: String,
    pub snapshot: Value,
    pub authoritative_observation: Value,
    pub expected: Expected,
    pub review: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expected {
    pub diagnosis: String,
    pub decisive_quotes: Vec<String>,
    pub unresolved_questions: Vec<String>,
    pub forbidden_conclusions: Vec<String>,
}

pub fn bounded_file(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.len() > maximum as u64 {
        return Err("fixture must be a bounded regular file".into());
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > maximum {
        return Err("fixture grew beyond its limit".into());
    }
    Ok(bytes)
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 80
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
pub type Cases = Vec<(Incident, Vec<u8>)>;

pub fn measurement_identity() -> Value {
    let mut host = sysinfo::System::new();
    host.refresh_memory();
    host.refresh_cpu_all();
    json!({"os":std::env::consts::OS,"architecture":std::env::consts::ARCH,
        "total_memory_bytes":host.total_memory(),"cpu":host.cpus().first().map(sysinfo::Cpu::brand),
        "build_profile":if cfg!(debug_assertions) {"unoptimized_test"} else {"optimized_test"},
        "workload":"ambient; not a controlled qualification workload",
        "harness_sha256":sha256_hex(include_bytes!("../incident_replay.rs")),
        "loader_sha256":sha256_hex(include_bytes!("mod.rs")),
        "redaction_code_sha256":sha256_hex(include_bytes!("../../src/evidence_view.rs")),
        "log_service_sha256":sha256_hex(include_bytes!("../../src/log_service.rs")),
        "compact_code_sha256":sha256_hex(include_bytes!("../../../pam_compact/src/compact.rs"))})
}

pub fn load(root: &Path) -> Result<(String, Cases), String> {
    let manifest_bytes = bounded_file(&root.join("manifest.json"), 64 * 1024)?;
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes).map_err(|e| e.to_string())?;
    if manifest.schema_version != 1
        || manifest.corpus_id != "pam-screening-v1"
        || manifest.purpose != "synthetic_screening_not_qualification"
        || manifest.entries.len() != 60
    {
        return Err("expected the frozen 60-case synthetic screening manifest".into());
    }
    let mut ids = BTreeSet::new();
    let mut families = BTreeSet::new();
    let mut source_hashes = BTreeSet::new();
    let mut cases = Vec::new();
    for entry in manifest.entries {
        if !identifier(&entry.case_id) || !ids.insert(entry.case_id.clone()) {
            return Err("invalid or duplicate case identifier".into());
        }
        let dir = root.join("cases").join(&entry.case_id);
        if std::fs::symlink_metadata(&dir)
            .map_err(|e| e.to_string())?
            .file_type()
            .is_symlink()
        {
            return Err("case directory cannot be a symlink".into());
        }
        let case_bytes = bounded_file(&dir.join("case.json"), 32 * 1024)?;
        let source = bounded_file(&dir.join("source.log"), 8 * 1024)?;
        if sha256_hex(&case_bytes) != entry.case_sha256
            || sha256_hex(&source) != entry.source_sha256
            || source.len() != entry.source_bytes
            || !source_hashes.insert(entry.source_sha256)
        {
            return Err("fixture digest/length mismatch or repeated source".into());
        }
        let case: Incident = serde_json::from_slice(&case_bytes).map_err(|e| e.to_string())?;
        validate(&case, &source)?;
        if case.case_id != entry.case_id || !families.insert(case.family_id.clone()) {
            return Err("case identity mismatch or family repeated in screening count".into());
        }
        cases.push((case, source));
    }
    for stage in ["git", "lint", "test", "build", "sonar", "publish"] {
        if cases.iter().filter(|(case, _)| case.stage == stage).count() != 10 {
            return Err("screening must contain ten cases per stage".into());
        }
    }
    Ok((sha256_hex(&manifest_bytes), cases))
}
pub(super) fn validate(case: &Incident, source: &[u8]) -> Result<(), String> {
    let text = std::str::from_utf8(source).map_err(|e| e.to_string())?;
    if case.schema_version != 1
        || case.split != "screening"
        || case.authenticity != "synthetic"
        || case.mode != "offline_evidence"
        || case.export_policy != "synthetic_only"
        || case.snapshot != json!({"path":"source.log"})
        || case.family_id.split('/').count() > 2
        || !case.family_id.split('/').all(identifier)
        || case.products.is_empty()
        || case.products.len() > 8
        || case.source_reference["kind"] != "authored"
        || case.review["author"].as_str().is_none()
        || case.review["status"] != "agent_adjudicated"
        || case.review["reviewer"].as_str().is_none()
        || case.review["reviewer"] == case.review["author"]
        || text.contains(&case.case_id)
        || case.task.contains(&case.case_id)
        || text.contains(&case.family_id)
        || case.task.contains(&case.family_id)
    {
        return Err(format!(
            "invalid authenticity/shape or descriptive-label leakage: {}",
            case.case_id
        ));
    }
    let status = case.authoritative_observation["status"]
        .as_str()
        .unwrap_or_default();
    if !["success", "failure", "unknown", "unsupported"].contains(&status)
        || !["infra", "code", "flake", "config", "unresolved"]
            .contains(&case.expected.diagnosis.as_str())
        || case.expected.decisive_quotes.is_empty()
        || case.expected.decisive_quotes.len() > 8
        || case.expected.unresolved_questions.len() > 8
        || case.expected.forbidden_conclusions.len() > 8
    {
        return Err("invalid bounded expected observations".into());
    }
    for quote in &case.expected.decisive_quotes {
        if quote.is_empty() || quote.len() > 2048 || text.match_indices(quote).count() != 1 {
            return Err(format!(
                "gold quote must name one exact source span: {}",
                case.case_id
            ));
        }
    }
    if case.expected.diagnosis == "unresolved" && case.expected.unresolved_questions.is_empty() {
        return Err("unresolved labels require a concrete missing question".into());
    }
    Ok(())
}

pub fn validate_map(compacted: &Compacted) {
    let mut offset = 0;
    for fragment in &compacted.fragments {
        assert_eq!(fragment.offset, offset);
        assert!(fragment.length > 0);
        offset = offset.checked_add(fragment.length).unwrap();
    }
    assert_eq!(offset, compacted.source_bytes);
    let mut rendered = compacted
        .fragments
        .iter()
        .map(|f| f.rendered.as_str())
        .collect::<String>();
    let footer = compacted
        .exit_status
        .map_or_else(|| "unknown".to_owned(), |status| status.to_string());
    writeln!(rendered, "[exit status: {footer}]").unwrap();
    assert_eq!(rendered, compacted.rendered_text);
}

pub fn retention(
    case: &Incident,
    source: &[u8],
    compacted: &Compacted,
    final_text: &str,
) -> Vec<Value> {
    let text = std::str::from_utf8(source).unwrap();
    case.expected.decisive_quotes.iter().map(|quote| {
        let start = text.find(quote).unwrap() as u64;
        let end = start + quote.len() as u64;
        let exact_raw_basis = compacted.source_sha256 == sha256_hex(source);
        let covered = exact_raw_basis && compacted.fragments.iter().filter(|fragment| fragment.offset < end && fragment.offset + fragment.length > start).all(|fragment| {
            matches!(fragment.kind, FragmentKind::Retained { .. })
        });
        json!({"raw_start":start,"raw_end":end,"quote_sha256":sha256_hex(quote.as_bytes()),
            "verbatim_present":final_text.contains(quote),"retained_record_covers_raw_span":covered,
            "raw_offset_comparison":if exact_raw_basis {"verified"} else {"not_asserted_after_redaction"}})
    }).collect()
}
