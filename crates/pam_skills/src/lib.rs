#![forbid(unsafe_code)]

mod model;

#[cfg(test)]
mod model_test;

pub use model::{
    AgentArtifact, AgentArtifactIdentity, ArtifactKind, ArtifactScope, InvalidAgentArtifact,
    LoadSemantics, MAX_ARTIFACT_LOGICAL_PATH_BYTES, MAX_ARTIFACT_NAME_BYTES, OriginAgent,
};
