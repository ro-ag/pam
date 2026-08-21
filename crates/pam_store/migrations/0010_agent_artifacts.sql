CREATE TABLE agent_artifacts (
    project_id TEXT NOT NULL
        REFERENCES projects(project_id) ON DELETE CASCADE,
    artifact_id TEXT NOT NULL
        CHECK (
            length(artifact_id) = 80
            AND substr(artifact_id, 1, 16) = 'artifact:sha256:'
            AND substr(artifact_id, 17) NOT GLOB '*[^0-9a-f]*'
        ),
    name TEXT NOT NULL
        CHECK (length(CAST(name AS BLOB)) BETWEEN 1 AND 256),
    logical_path TEXT NOT NULL
        CHECK (length(CAST(logical_path AS BLOB)) BETWEEN 1 AND 4096),
    kind TEXT NOT NULL
        CHECK (kind IN (
            'skill', 'plugin', 'agent', 'hook', 'instruction', 'config',
            'prompt', 'rule', 'embedding', 'reranker', 'compressor',
            'analyzer', 'wasm_component'
        )),
    scope TEXT NOT NULL
        CHECK (scope IN ('managed', 'system', 'user', 'project', 'local', 'plugin')),
    origin TEXT NOT NULL
        CHECK (origin IN ('claude_code', 'codex', 'cursor', 'pam')),
    load_semantics TEXT NOT NULL
        CHECK (load_semantics IN (
            'always', 'explicit', 'model_selected', 'path_conditional',
            'event_triggered', 'configuration_layer', 'plugin_enabled',
            'disabled_or_installed_only', 'unavailable'
        )),
    content_hash TEXT NOT NULL
        CHECK (
            length(content_hash) = 71
            AND substr(content_hash, 1, 7) = 'sha256:'
            AND substr(content_hash, 8) NOT GLOB '*[^0-9a-f]*'
        ),
    first_seen_at_ms INTEGER NOT NULL CHECK (first_seen_at_ms >= 0),
    last_changed_at_ms INTEGER NOT NULL CHECK (last_changed_at_ms >= first_seen_at_ms),
    removed_at_ms INTEGER
        CHECK (removed_at_ms IS NULL OR removed_at_ms >= last_changed_at_ms),
    PRIMARY KEY (project_id, artifact_id),
    UNIQUE (project_id, origin, kind, scope, logical_path)
) STRICT, WITHOUT ROWID;

CREATE INDEX agent_artifacts_active_order
    ON agent_artifacts(project_id, origin, scope, kind, logical_path)
    WHERE removed_at_ms IS NULL;
