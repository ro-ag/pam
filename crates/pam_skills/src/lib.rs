#![forbid(unsafe_code)]

mod claude;
mod model;
mod scan;

#[cfg(test)]
mod claude_test;
#[cfg(test)]
mod model_test;
#[cfg(test)]
mod scan_test;

pub use claude::{ClaudePluginRoot, ClaudeScanRoots, scan_claude_code};
pub use model::{
    AgentArtifact, AgentArtifactIdentity, ArtifactKind, ArtifactScope, InvalidAgentArtifact,
    LoadSemantics, MAX_ARTIFACT_LOGICAL_PATH_BYTES, MAX_ARTIFACT_NAME_BYTES, OriginAgent,
};
pub use scan::{ScanDiagnostic, ScanDiagnosticKind, ScanLimits, ScanReport};
