use pam_skills::{AgentArtifact, AgentArtifactId};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredAgentArtifact {
    pub id: AgentArtifactId,
    pub artifact: AgentArtifact,
    pub first_seen_at_ms: u64,
    pub last_changed_at_ms: u64,
    pub removed_at_ms: Option<u64>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SkillInventoryDrift {
    pub added: Vec<StoredAgentArtifact>,
    pub changed: Vec<StoredAgentArtifact>,
    pub removed: Vec<StoredAgentArtifact>,
    pub resurrected: Vec<StoredAgentArtifact>,
}

impl SkillInventoryDrift {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.added.is_empty()
            && self.changed.is_empty()
            && self.removed.is_empty()
            && self.resurrected.is_empty()
    }
}
