#![forbid(unsafe_code)]

mod claude;
mod codex;
mod codex_trust;
mod cursor;
mod local;
mod model;
mod scan;

#[cfg(test)]
mod claude_test;
#[cfg(test)]
mod codex_test;
#[cfg(test)]
mod codex_trust_test;
#[cfg(test)]
mod cursor_test;
#[cfg(test)]
mod fixture_test;
#[cfg(test)]
mod local_test;
#[cfg(test)]
mod model_test;
#[cfg(test)]
mod scan_test;

pub use claude::{ClaudePluginRoot, ClaudeScanRoots, scan_claude_code};
pub use codex::{CodexScanRoots, scan_codex};
pub use codex_trust::{CodexProjectTrust, CodexProjectTrustError, resolve_codex_project_trust};
pub use cursor::{
    CursorGlobalRuleSource, CursorGlobalRulesStatus, CursorScanReport, CursorScanRoots, scan_cursor,
};
pub use local::{
    LocalInventoryError, LocalInventoryReport, LocalInventoryRoots, scan_local_inventory,
};
pub use model::{
    AgentArtifact, AgentArtifactId, AgentArtifactIdentity, ArtifactKind, ArtifactScope,
    InvalidAgentArtifact, InvalidAgentArtifactId, InvalidArtifactEnum, LoadSemantics,
    MAX_ARTIFACT_LOGICAL_PATH_BYTES, MAX_ARTIFACT_NAME_BYTES, OriginAgent,
};
pub use scan::{ScanDiagnostic, ScanDiagnosticKind, ScanLimits, ScanReport};
