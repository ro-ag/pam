use pam_core::ContentDigest;
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use super::{
    AgentArtifact, ArtifactKind, ArtifactScope, LoadSemantics, OriginAgent,
    audit::{
        STATIC_FOOTPRINT_SCHEMA_VERSION, StaticFootprintError, TokenEstimator,
        build_static_footprint,
    },
    scan::{ScanLimits, ScanSession},
};

const NATIVE_LF: &[u8] = include_bytes!("../tests/fixtures/native-project/.claude/rules/native.md");
const NATIVE_CRLF: &[u8] =
    include_bytes!("../tests/fixtures/native-project/workspace child/.codex/config.toml");
const STATIC_FOOTPRINT_GOLDEN: &[u8] =
    include_bytes!("../tests/fixtures/audit-golden/static-footprint.json");

fn artifact(path: &str, semantics: LoadSemantics, hash_byte: u8) -> AgentArtifact {
    artifact_with(
        path,
        semantics,
        hash_byte,
        OriginAgent::Codex,
        ArtifactScope::Project,
    )
}

fn artifact_with(
    path: &str,
    semantics: LoadSemantics,
    hash_byte: u8,
    origin: OriginAgent,
    scope: ArtifactScope,
) -> AgentArtifact {
    AgentArtifact::new(
        path,
        path,
        ArtifactKind::Instruction,
        scope,
        origin,
        semantics,
        ContentDigest::from_sha256([hash_byte; 32]),
    )
    .unwrap()
}

fn complete_scan(entries: [(&str, LoadSemantics, u8, &[u8]); 5]) -> super::ScanReport {
    let mut session = ScanSession::new(ScanLimits::default());
    for (path, semantics, hash_byte, content) in entries {
        session.push_artifact_with_content(artifact(path, semantics, hash_byte), content.to_vec());
    }
    session.finish()
}

fn golden_artifact(
    name: &str,
    path: &str,
    kind: ArtifactKind,
    scope: ArtifactScope,
    origin: OriginAgent,
    semantics: LoadSemantics,
    source: &[u8],
) -> AgentArtifact {
    AgentArtifact::new(
        name,
        path,
        kind,
        scope,
        origin,
        semantics,
        ContentDigest::from_sha256(Sha256::digest(source).into()),
    )
    .unwrap()
}

#[test]
#[allow(clippy::too_many_lines)] // One golden contract covers every footprint dimension together.
fn complete_static_footprint_pretty_json_matches_checked_in_golden_bytes() {
    assert!(NATIVE_LF.contains(&b'\n'));
    assert!(!NATIVE_LF.contains(&b'\r'));
    assert!(NATIVE_CRLF.windows(2).any(|pair| pair == b"\r\n"));
    let normalized_lf = String::from_utf8(NATIVE_CRLF.to_vec())
        .unwrap()
        .replace("\r\n", "\n")
        .into_bytes();
    assert_eq!(NATIVE_CRLF.len(), normalized_lf.len() + 1);
    assert_eq!("é🙂\n".len(), 7);

    let entries = vec![
        (
            golden_artifact(
                "native LF",
                "claude/native-lf.md",
                ArtifactKind::Rule,
                ArtifactScope::User,
                OriginAgent::ClaudeCode,
                LoadSemantics::Always,
                NATIVE_LF,
            ),
            NATIVE_LF.to_vec(),
        ),
        (
            golden_artifact(
                "line ending LF",
                "codex/line-endings-lf.toml",
                ArtifactKind::Config,
                ArtifactScope::Project,
                OriginAgent::Codex,
                LoadSemantics::Always,
                &normalized_lf,
            ),
            normalized_lf,
        ),
        (
            golden_artifact(
                "line ending CRLF",
                "cursor/line-endings-crlf.toml",
                ArtifactKind::Config,
                ArtifactScope::Project,
                OriginAgent::Cursor,
                LoadSemantics::Always,
                NATIVE_CRLF,
            ),
            NATIVE_CRLF.to_vec(),
        ),
        (
            golden_artifact(
                "unicode",
                "pam/unicode.md",
                ArtifactKind::Instruction,
                ArtifactScope::Managed,
                OriginAgent::Pam,
                LoadSemantics::Always,
                "é🙂\n".as_bytes(),
            ),
            "é🙂\n".as_bytes().to_vec(),
        ),
        (
            golden_artifact(
                "empty",
                "codex/empty.md",
                ArtifactKind::Instruction,
                ArtifactScope::Local,
                OriginAgent::Codex,
                LoadSemantics::Always,
                b"",
            ),
            Vec::new(),
        ),
        (
            golden_artifact(
                "ceil four",
                "cursor/four.txt",
                ArtifactKind::Prompt,
                ArtifactScope::Plugin,
                OriginAgent::Cursor,
                LoadSemantics::Always,
                b"1234",
            ),
            b"1234".to_vec(),
        ),
        (
            golden_artifact(
                "duplicate A",
                "claude/duplicate-a.md",
                ArtifactKind::Instruction,
                ArtifactScope::Project,
                OriginAgent::ClaudeCode,
                LoadSemantics::Always,
                b"same",
            ),
            b"same".to_vec(),
        ),
        (
            golden_artifact(
                "duplicate B",
                "codex/duplicate-b.md",
                ArtifactKind::Instruction,
                ArtifactScope::System,
                OriginAgent::Codex,
                LoadSemantics::Always,
                b"same",
            ),
            b"same".to_vec(),
        ),
        (
            golden_artifact(
                "ceil one",
                "pam/one.txt",
                ArtifactKind::Prompt,
                ArtifactScope::User,
                OriginAgent::Pam,
                LoadSemantics::Always,
                b"x",
            ),
            b"x".to_vec(),
        ),
        (
            golden_artifact(
                "excluded",
                "pam/excluded.md",
                ArtifactKind::Instruction,
                ArtifactScope::Managed,
                OriginAgent::Pam,
                LoadSemantics::ModelSelected,
                b"excluded source must not affect the footprint",
            ),
            b"excluded source must not affect the footprint".to_vec(),
        ),
    ];
    let mut session = ScanSession::new(ScanLimits::default());
    for (artifact, source) in entries {
        session.push_artifact_with_content(artifact, source);
    }
    let scan = session.finish();
    assert!(scan.complete(), "{:?}", scan.diagnostics());

    let footprint = build_static_footprint(&scan).unwrap();
    assert_eq!(footprint.always_loaded_artifact_count(), 9);
    assert_eq!(footprint.all_session_raw_bytes(), 156);
    assert_eq!(footprint.all_session_estimated_tokens(), 42);
    assert!(
        !footprint
            .artifacts()
            .iter()
            .any(|artifact| artifact.logical_path() == "pam/excluded.md")
    );
    assert_eq!(
        footprint
            .artifacts()
            .iter()
            .map(super::audit::StaticFootprintArtifact::rank)
            .collect::<Vec<_>>(),
        (1..=9).collect::<Vec<_>>()
    );
    for pair in footprint.artifacts().windows(2) {
        if pair[0].estimated_tokens() == pair[1].estimated_tokens()
            && pair[0].raw_bytes() == pair[1].raw_bytes()
        {
            assert!(pair[0].id() < pair[1].id());
        }
    }
    let line_lf = footprint
        .artifacts()
        .iter()
        .find(|artifact| artifact.logical_path() == "codex/line-endings-lf.toml")
        .unwrap();
    let line_crlf = footprint
        .artifacts()
        .iter()
        .find(|artifact| artifact.logical_path() == "cursor/line-endings-crlf.toml")
        .unwrap();
    assert_eq!((line_lf.raw_bytes(), line_lf.estimated_tokens()), (45, 12));
    assert_eq!(
        (line_crlf.raw_bytes(), line_crlf.estimated_tokens()),
        (46, 12)
    );
    let duplicates = footprint
        .artifacts()
        .iter()
        .filter(|artifact| artifact.name().starts_with("duplicate "))
        .collect::<Vec<_>>();
    assert_eq!(duplicates.len(), 2);
    assert_ne!(duplicates[0].id(), duplicates[1].id());
    assert_eq!(duplicates[0].content_hash(), duplicates[1].content_hash());
    assert_eq!(
        footprint
            .origin_agent_session_totals()
            .iter()
            .map(|total| (
                total.origin(),
                total.artifact_count(),
                total.raw_bytes(),
                total.estimated_tokens(),
            ))
            .collect::<Vec<_>>(),
        vec![
            (OriginAgent::ClaudeCode, 2, 49, 13),
            (OriginAgent::Codex, 3, 49, 13),
            (OriginAgent::Cursor, 2, 50, 13),
            (OriginAgent::Pam, 2, 8, 3),
        ]
    );
    assert_eq!(
        footprint
            .all_session_scope_totals()
            .iter()
            .map(|total| (
                total.scope(),
                total.artifact_count(),
                total.raw_bytes(),
                total.estimated_tokens(),
            ))
            .collect::<Vec<_>>(),
        vec![
            (ArtifactScope::Managed, 1, 7, 2),
            (ArtifactScope::System, 1, 4, 1),
            (ArtifactScope::User, 2, 46, 13),
            (ArtifactScope::Project, 3, 95, 25),
            (ArtifactScope::Local, 1, 0, 0),
            (ArtifactScope::Plugin, 1, 4, 1),
        ]
    );

    let mut pretty_json = serde_json::to_vec_pretty(&footprint).unwrap();
    pretty_json.push(b'\n');
    assert_eq!(
        pretty_json.as_slice(),
        STATIC_FOOTPRINT_GOLDEN,
        "actual golden:\n{}",
        String::from_utf8_lossy(&pretty_json)
    );
}

#[test]
fn static_footprint_includes_only_always_loaded_sources_in_rank_order() {
    let scan = complete_scan([
        ("z.md", LoadSemantics::Always, 1, b"12345"),
        (
            "excluded.md",
            LoadSemantics::ModelSelected,
            2,
            b"private excluded body",
        ),
        ("empty.md", LoadSemantics::Always, 3, b""),
        ("four.md", LoadSemantics::Always, 4, b"1234"),
        ("one.md", LoadSemantics::Always, 5, b"1"),
    ]);

    let footprint = build_static_footprint(&scan).unwrap();

    assert_eq!(footprint.schema_version(), STATIC_FOOTPRINT_SCHEMA_VERSION);
    assert_eq!(footprint.estimator(), TokenEstimator::RawBytesDiv4CeilV1);
    assert_eq!(footprint.estimator().as_str(), "raw_bytes_div_4_ceil_v1");
    assert_eq!(footprint.always_loaded_artifact_count(), 4);
    assert_eq!(footprint.all_session_raw_bytes(), 10);
    assert_eq!(footprint.all_session_estimated_tokens(), 4);
    assert_eq!(
        footprint
            .artifacts()
            .iter()
            .map(super::audit::StaticFootprintArtifact::logical_path)
            .collect::<Vec<_>>(),
        vec!["z.md", "four.md", "one.md", "empty.md"]
    );
    assert_eq!(
        footprint
            .artifacts()
            .iter()
            .map(super::audit::StaticFootprintArtifact::rank)
            .collect::<Vec<_>>(),
        vec![1, 2, 3, 4]
    );
    assert!(footprint.artifacts().iter().all(|artifact| {
        artifact.load_semantics() == LoadSemantics::Always
            && artifact.kind() == ArtifactKind::Instruction
            && artifact.scope() == ArtifactScope::Project
            && artifact.origin() == OriginAgent::Codex
            && !artifact.name().is_empty()
            && !artifact.id().as_str().is_empty()
            && artifact.content_hash().as_str().starts_with("sha256:")
    }));
}

#[test]
fn ranking_uses_tokens_then_bytes_then_stable_artifact_id() {
    let scan = complete_scan([
        ("five-z.md", LoadSemantics::Always, 1, b"12345"),
        ("zero.md", LoadSemantics::Always, 2, b""),
        ("eight.md", LoadSemantics::Always, 3, b"12345678"),
        ("nine.md", LoadSemantics::Always, 4, b"123456789"),
        ("five-a.md", LoadSemantics::Always, 5, b"abcde"),
    ]);

    let footprint = build_static_footprint(&scan).unwrap();
    let artifacts = footprint.artifacts();

    assert_eq!(
        artifacts
            .iter()
            .map(super::audit::StaticFootprintArtifact::rank)
            .collect::<Vec<_>>(),
        vec![1, 2, 3, 4, 5]
    );
    assert_eq!(artifacts[0].logical_path(), "nine.md");
    assert_eq!(artifacts[1].logical_path(), "eight.md");
    assert_eq!(artifacts[1].estimated_tokens(), 2);
    assert_eq!(artifacts[2].estimated_tokens(), 2);
    assert_eq!(artifacts[3].estimated_tokens(), 2);
    assert_eq!(artifacts[2].raw_bytes(), 5);
    assert_eq!(artifacts[3].raw_bytes(), 5);
    assert!(artifacts[2].id() < artifacts[3].id());
    assert_eq!(artifacts[4].logical_path(), "zero.md");
}

#[test]
fn origin_sessions_and_all_session_scopes_have_deterministic_totals() {
    let mut session = ScanSession::new(ScanLimits::default());
    for (artifact, content) in [
        (
            artifact_with(
                "claude-user.md",
                LoadSemantics::Always,
                1,
                OriginAgent::ClaudeCode,
                ArtifactScope::User,
            ),
            b"1234".as_slice(),
        ),
        (
            artifact_with(
                "claude-project.md",
                LoadSemantics::Always,
                2,
                OriginAgent::ClaudeCode,
                ArtifactScope::Project,
            ),
            b"12345".as_slice(),
        ),
        (
            artifact_with(
                "codex-project.md",
                LoadSemantics::Always,
                3,
                OriginAgent::Codex,
                ArtifactScope::Project,
            ),
            b"12345678".as_slice(),
        ),
        (
            artifact_with(
                "cursor-user.md",
                LoadSemantics::Always,
                4,
                OriginAgent::Cursor,
                ArtifactScope::User,
            ),
            b"1".as_slice(),
        ),
        (
            artifact_with(
                "excluded.md",
                LoadSemantics::Explicit,
                5,
                OriginAgent::Pam,
                ArtifactScope::Managed,
            ),
            b"not counted".as_slice(),
        ),
    ] {
        session.push_artifact_with_content(artifact, content.to_vec());
    }

    let footprint = build_static_footprint(&session.finish()).unwrap();
    let origin_totals = footprint.origin_agent_session_totals();
    let scope_totals = footprint.all_session_scope_totals();

    assert_eq!(
        origin_totals
            .iter()
            .map(|totals| (
                totals.origin(),
                totals.artifact_count(),
                totals.raw_bytes(),
                totals.estimated_tokens(),
            ))
            .collect::<Vec<_>>(),
        vec![
            (OriginAgent::ClaudeCode, 2, 9, 3),
            (OriginAgent::Codex, 1, 8, 2),
            (OriginAgent::Cursor, 1, 1, 1),
        ]
    );
    assert_eq!(
        scope_totals
            .iter()
            .map(|totals| (
                totals.scope(),
                totals.artifact_count(),
                totals.raw_bytes(),
                totals.estimated_tokens(),
            ))
            .collect::<Vec<_>>(),
        vec![
            (ArtifactScope::User, 2, 5, 2),
            (ArtifactScope::Project, 2, 13, 4),
        ]
    );
    assert_eq!(footprint.always_loaded_artifact_count(), 4);
    assert_eq!(footprint.all_session_raw_bytes(), 18);
    assert_eq!(footprint.all_session_estimated_tokens(), 6);
}

#[test]
fn token_estimate_uses_exact_ceil_boundaries_including_empty_content() {
    let scan = complete_scan([
        ("zero.md", LoadSemantics::Always, 1, b""),
        ("one.md", LoadSemantics::Always, 2, b"1"),
        ("four.md", LoadSemantics::Always, 3, b"1234"),
        ("five.md", LoadSemantics::Always, 4, b"12345"),
        ("excluded.md", LoadSemantics::Explicit, 5, b"123456789"),
    ]);

    let footprint = build_static_footprint(&scan).unwrap();
    let sizes = footprint
        .artifacts()
        .iter()
        .map(|artifact| {
            (
                artifact.logical_path(),
                artifact.raw_bytes(),
                artifact.estimated_tokens(),
            )
        })
        .collect::<Vec<_>>();

    assert!(sizes.contains(&("zero.md", 0, 0)));
    assert!(sizes.contains(&("one.md", 1, 1)));
    assert!(sizes.contains(&("four.md", 4, 1)));
    assert!(sizes.contains(&("five.md", 5, 2)));
    assert_eq!(footprint.all_session_raw_bytes(), 10);
    assert_eq!(footprint.all_session_estimated_tokens(), 4);
}

#[test]
fn missing_always_loaded_source_returns_only_the_stable_artifact_id() {
    let missing = artifact("private/instructions.md", LoadSemantics::Always, 9);
    let expected_id = missing.id();
    let scan = super::ScanReport::from_artifacts([missing]);

    let error = build_static_footprint(&scan).unwrap_err();

    assert_eq!(
        error,
        StaticFootprintError::MissingAlwaysLoadedSource(expected_id.clone())
    );
    assert!(error.to_string().contains(expected_id.as_str()));
    assert!(!error.to_string().contains("private/instructions.md"));
}

#[test]
fn serialized_and_debug_reports_never_contain_instruction_bodies() {
    let secret = b"private instruction body that must not escape";
    let scan = complete_scan([
        ("always.md", LoadSemantics::Always, 1, secret),
        (
            "explicit.md",
            LoadSemantics::Explicit,
            2,
            b"other private body",
        ),
        ("empty.md", LoadSemantics::Always, 3, b""),
        ("one.md", LoadSemantics::Always, 4, b"x"),
        ("four.md", LoadSemantics::Always, 5, b"xxxx"),
    ]);
    let footprint = build_static_footprint(&scan).unwrap();

    let serialized = serde_json::to_string(&footprint).unwrap();
    let debug = format!("{footprint:?}");
    let scan_serialized = serde_json::to_string(&scan).unwrap();
    let scan_debug = format!("{scan:?}");
    for output in [&serialized, &debug, &scan_serialized, &scan_debug] {
        assert!(!output.contains("private instruction body"));
        assert!(!output.contains("other private body"));
    }

    let value = serde_json::from_str::<Value>(&serialized).unwrap();
    assert_eq!(value["schemaVersion"], STATIC_FOOTPRINT_SCHEMA_VERSION);
    assert_eq!(value["estimator"], "raw_bytes_div_4_ceil_v1");
    assert_eq!(value["alwaysLoadedArtifactCount"], 4);
    assert_eq!(value["allSessionRawBytes"], 50);
    assert_eq!(value["allSessionEstimatedTokens"], 14);
    assert_eq!(value["artifacts"][0]["rank"], 1);
    assert!(value["artifacts"][0].get("rawBytes").is_some());
    assert!(value["artifacts"][0].get("estimatedTokens").is_some());
    assert_eq!(value["originAgentSessionTotals"][0]["origin"], "codex");
    assert_eq!(value["originAgentSessionTotals"][0]["artifactCount"], 4);
    assert_eq!(value["originAgentSessionTotals"][0]["rawBytes"], 50);
    assert_eq!(value["originAgentSessionTotals"][0]["estimatedTokens"], 14);
    assert_eq!(value["allSessionScopeTotals"][0]["scope"], "project");
    assert_eq!(value["allSessionScopeTotals"][0]["artifactCount"], 4);
    assert_eq!(value["allSessionScopeTotals"][0]["rawBytes"], 50);
    assert_eq!(value["allSessionScopeTotals"][0]["estimatedTokens"], 14);

    let round_trip = serde_json::from_str(&serialized).unwrap();
    assert_eq!(footprint, round_trip);
}
