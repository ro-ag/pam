use pam_skills::{AgentArtifact, AgentArtifactId};

/// Maximum removed artifact identities retained for one project.
///
/// Active artifacts do not count toward this limit. Tombstones are retained newest
/// removal first, with artifact identity as the deterministic tie-break. A retained
/// tombstone preserves first-seen history if that identity is resurrected; identities
/// older than the cap are treated as new if they return.
pub const MAX_SKILL_INVENTORY_TOMBSTONES_PER_PROJECT: usize = 4_096;

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
