use std::{collections::BTreeSet, str::FromStr as _};

use pam_core::ContentDigest;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::json;

use super::{
    AgentArtifact, AgentArtifactId, ArtifactKind, ArtifactScope, InvalidAgentArtifact,
    LoadSemantics, MAX_ARTIFACT_LOGICAL_PATH_BYTES, MAX_ARTIFACT_NAME_BYTES, OriginAgent,
};

fn digest(byte: u8) -> ContentDigest {
    ContentDigest::from_sha256([byte; 32])
}

fn artifact(path: impl Into<String>, hash_byte: u8) -> AgentArtifact {
    AgentArtifact::new(
        "deploy",
        path,
        ArtifactKind::Skill,
        ArtifactScope::Project,
        OriginAgent::ClaudeCode,
        LoadSemantics::ModelSelected,
        digest(hash_byte),
    )
    .unwrap()
}

fn assert_serde_names<T>(cases: &[(T, &str)])
where
    T: Copy + std::fmt::Debug + Eq + Serialize + DeserializeOwned,
{
    for &(value, name) in cases {
        let json = format!("\"{name}\"");
        assert_eq!(serde_json::to_string(&value).unwrap(), json);
        assert_eq!(serde_json::from_str::<T>(&json).unwrap(), value);
    }
}

#[test]
fn enum_serialization_covers_every_normalized_value() {
    assert_serde_names(&[
        (ArtifactKind::Skill, "skill"),
        (ArtifactKind::Plugin, "plugin"),
        (ArtifactKind::Agent, "agent"),
        (ArtifactKind::Hook, "hook"),
        (ArtifactKind::Instruction, "instruction"),
        (ArtifactKind::Config, "config"),
        (ArtifactKind::Prompt, "prompt"),
        (ArtifactKind::Rule, "rule"),
        (ArtifactKind::Embedding, "embedding"),
        (ArtifactKind::Reranker, "reranker"),
        (ArtifactKind::Compressor, "compressor"),
        (ArtifactKind::Analyzer, "analyzer"),
        (ArtifactKind::WasmComponent, "wasm_component"),
    ]);
    assert_serde_names(&[
        (ArtifactScope::Managed, "managed"),
        (ArtifactScope::System, "system"),
        (ArtifactScope::User, "user"),
        (ArtifactScope::Project, "project"),
        (ArtifactScope::Local, "local"),
        (ArtifactScope::Plugin, "plugin"),
    ]);
    assert_serde_names(&[
        (OriginAgent::ClaudeCode, "claude_code"),
        (OriginAgent::Codex, "codex"),
        (OriginAgent::Cursor, "cursor"),
        (OriginAgent::Pam, "pam"),
    ]);
    assert_serde_names(&[
        (LoadSemantics::Always, "always"),
        (LoadSemantics::Explicit, "explicit"),
        (LoadSemantics::ModelSelected, "model_selected"),
        (LoadSemantics::PathConditional, "path_conditional"),
        (LoadSemantics::EventTriggered, "event_triggered"),
        (LoadSemantics::ConfigurationLayer, "configuration_layer"),
        (LoadSemantics::PluginEnabled, "plugin_enabled"),
        (
            LoadSemantics::DisabledOrInstalledOnly,
            "disabled_or_installed_only",
        ),
        (LoadSemantics::Unavailable, "unavailable"),
    ]);
}

#[test]
fn artifact_round_trips_with_deterministic_json() {
    let artifact = artifact(".claude\\skills\\deploy\\SKILL.md", 0xab);
    assert_eq!(artifact.name(), "deploy");
    assert_eq!(artifact.logical_path(), ".claude/skills/deploy/SKILL.md");
    assert_eq!(artifact.kind(), ArtifactKind::Skill);
    assert_eq!(artifact.scope(), ArtifactScope::Project);
    assert_eq!(artifact.origin(), OriginAgent::ClaudeCode);
    assert_eq!(artifact.load_semantics(), LoadSemantics::ModelSelected);
    assert_eq!(artifact.content_hash(), &digest(0xab));

    let serialized = serde_json::to_string(&artifact).unwrap();
    assert_eq!(
        serialized,
        concat!(
            r#"{"name":"deploy","logical_path":".claude/skills/deploy/SKILL.md","kind":"skill","scope":"project","origin":"claude_code","load_semantics":"model_selected","content_hash":"sha256:"#,
            "abababababababababababababababababababababababababababababababab",
            r#""}"#,
        )
    );
    assert_eq!(
        serde_json::from_str::<AgentArtifact>(&serialized).unwrap(),
        artifact
    );
}

#[test]
fn name_validation_enforces_nul_and_byte_bounds() {
    let maximum = "a".repeat(MAX_ARTIFACT_NAME_BYTES);
    assert_eq!(
        AgentArtifact::new(
            &maximum,
            "skill.md",
            ArtifactKind::Skill,
            ArtifactScope::User,
            OriginAgent::Codex,
            LoadSemantics::Explicit,
            digest(1),
        )
        .unwrap()
        .name(),
        maximum
    );

    for invalid in [
        String::new(),
        "has\0nul".to_owned(),
        "a".repeat(MAX_ARTIFACT_NAME_BYTES + 1),
    ] {
        assert!(matches!(
            AgentArtifact::new(
                invalid,
                "skill.md",
                ArtifactKind::Skill,
                ArtifactScope::User,
                OriginAgent::Codex,
                LoadSemantics::Explicit,
                digest(1),
            ),
            Err(InvalidAgentArtifact::Name)
        ));
    }
}

#[test]
fn logical_path_validation_enforces_relative_canonical_components() {
    let maximum = "a".repeat(MAX_ARTIFACT_LOGICAL_PATH_BYTES);
    assert_eq!(artifact(&maximum, 1).logical_path(), maximum);

    let invalid = [
        String::new(),
        "has\0nul".to_owned(),
        "/absolute/path".to_owned(),
        "\\\\server\\share".to_owned(),
        "C:\\Users\\skill.md".to_owned(),
        ".".to_owned(),
        "..".to_owned(),
        "./skill.md".to_owned(),
        "skills/./skill.md".to_owned(),
        "skills/../skill.md".to_owned(),
        "skills//skill.md".to_owned(),
        "skills/".to_owned(),
        "a".repeat(MAX_ARTIFACT_LOGICAL_PATH_BYTES + 1),
    ];
    for path in invalid {
        assert!(matches!(
            AgentArtifact::new(
                "deploy",
                path,
                ArtifactKind::Skill,
                ArtifactScope::Project,
                OriginAgent::Cursor,
                LoadSemantics::PathConditional,
                digest(1),
            ),
            Err(InvalidAgentArtifact::LogicalPath)
        ));
    }
}

#[test]
fn deserialization_cannot_bypass_validation_or_add_fields() {
    let mut value = serde_json::to_value(artifact("skill.md", 1)).unwrap();
    value["name"] = json!("");
    assert!(serde_json::from_value::<AgentArtifact>(value).is_err());

    let mut value = serde_json::to_value(artifact("skill.md", 1)).unwrap();
    value["logical_path"] = json!("../skill.md");
    assert!(serde_json::from_value::<AgentArtifact>(value).is_err());

    let mut value = serde_json::to_value(artifact("skill.md", 1)).unwrap();
    value["unexpected"] = json!(true);
    assert!(serde_json::from_value::<AgentArtifact>(value).is_err());
}

#[test]
fn identity_and_total_order_are_stable_across_content_changes() {
    let older = artifact("skills/deploy/SKILL.md", 1);
    let newer = artifact("skills/deploy/SKILL.md", 2);
    assert_eq!(older.identity(), newer.identity());
    assert_eq!(older.id(), newer.id());
    assert!(older < newer);

    let mut ordered = BTreeSet::new();
    ordered.insert(artifact("skills/z/SKILL.md", 1));
    ordered.insert(artifact("skills/a/SKILL.md", 1));
    let paths = ordered
        .iter()
        .map(AgentArtifact::logical_path)
        .collect::<Vec<_>>();
    assert_eq!(paths, ["skills/a/SKILL.md", "skills/z/SKILL.md"]);
}

#[test]
fn stable_id_is_canonical_and_identity_bound() {
    let first = artifact("skills/deploy/SKILL.md", 1);
    let same_identity = artifact("skills/deploy/SKILL.md", 2);
    let other_path = artifact("skills/release/SKILL.md", 1);
    assert_eq!(first.id(), same_identity.id());
    assert_ne!(first.id(), other_path.id());
    assert_eq!(
        AgentArtifactId::from_str(first.id().as_str()).unwrap(),
        first.id()
    );
    assert_eq!(
        serde_json::from_str::<AgentArtifactId>(&serde_json::to_string(&first.id()).unwrap())
            .unwrap(),
        first.id()
    );
    for invalid in ["", "sha256:00", "artifact:sha256:AB", "artifact:sha256:00"] {
        assert!(AgentArtifactId::from_str(invalid).is_err());
    }
}

#[test]
fn enum_text_round_trips_match_serde_names() {
    for value in [ArtifactKind::Skill, ArtifactKind::WasmComponent] {
        assert_eq!(ArtifactKind::from_str(value.as_str()).unwrap(), value);
    }
    for value in [ArtifactScope::Managed, ArtifactScope::Local] {
        assert_eq!(ArtifactScope::from_str(value.as_str()).unwrap(), value);
    }
    for value in [OriginAgent::ClaudeCode, OriginAgent::Pam] {
        assert_eq!(OriginAgent::from_str(value.as_str()).unwrap(), value);
    }
    for value in [LoadSemantics::Always, LoadSemantics::Unavailable] {
        assert_eq!(LoadSemantics::from_str(value.as_str()).unwrap(), value);
    }
    assert!(ArtifactKind::from_str("unknown").is_err());
}
