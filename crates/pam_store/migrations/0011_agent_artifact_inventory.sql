CREATE TABLE agent_artifact_inventory (
    project_id TEXT PRIMARY KEY
        REFERENCES projects(project_id) ON DELETE CASCADE,
    observed_at_ms INTEGER NOT NULL CHECK (observed_at_ms >= 0)
) STRICT, WITHOUT ROWID;

INSERT INTO agent_artifact_inventory(project_id, observed_at_ms)
SELECT project_id, MAX(COALESCE(removed_at_ms, last_changed_at_ms))
FROM agent_artifacts
GROUP BY project_id;

CREATE INDEX agent_artifacts_removed_order
    ON agent_artifacts(project_id, removed_at_ms DESC, artifact_id)
    WHERE removed_at_ms IS NOT NULL;
