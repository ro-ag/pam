CREATE TABLE project_policies (
    project_id TEXT PRIMARY KEY NOT NULL REFERENCES projects(project_id),
    version INTEGER NOT NULL CHECK (version > 0),
    default_effect TEXT NOT NULL CHECK (default_effect = 'deny'),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0)
) STRICT, WITHOUT ROWID;

CREATE TABLE capability_grants (
    grant_id TEXT PRIMARY KEY NOT NULL,
    caller_id TEXT NOT NULL REFERENCES callers(caller_id),
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    capability TEXT NOT NULL CHECK (length(capability) BETWEEN 1 AND 128),
    resource_kind TEXT NOT NULL CHECK (resource_kind IN ('any', 'exact')),
    resource TEXT CHECK (length(resource) BETWEEN 1 AND 512),
    effect TEXT NOT NULL CHECK (effect IN ('allow', 'deny')),
    approval TEXT NOT NULL CHECK (approval IN ('none', 'once')),
    expires_at_ms INTEGER CHECK (expires_at_ms >= 0),
    revoked_at_ms INTEGER CHECK (revoked_at_ms >= 0),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    CHECK (
        (resource_kind = 'any' AND resource IS NULL)
        OR (resource_kind = 'exact' AND resource IS NOT NULL)
    )
) STRICT, WITHOUT ROWID;

CREATE INDEX capability_grants_lookup
    ON capability_grants(caller_id, project_id, capability, revoked_at_ms, expires_at_ms);

CREATE TABLE approvals (
    approval_id TEXT PRIMARY KEY NOT NULL,
    caller_id TEXT NOT NULL REFERENCES callers(caller_id),
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    capability TEXT NOT NULL CHECK (length(capability) BETWEEN 1 AND 128),
    resource TEXT NOT NULL CHECK (length(resource) BETWEEN 1 AND 512),
    effect_fingerprint BLOB NOT NULL CHECK (length(effect_fingerprint) = 32),
    state TEXT NOT NULL
        CHECK (state IN ('requested', 'approved', 'denied', 'consumed', 'expired')),
    requested_at_ms INTEGER NOT NULL CHECK (requested_at_ms >= 0),
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms > requested_at_ms),
    decided_by TEXT REFERENCES callers(caller_id),
    decided_at_ms INTEGER CHECK (decided_at_ms >= requested_at_ms),
    consumed_at_ms INTEGER CHECK (consumed_at_ms >= requested_at_ms),
    CHECK (
        (state = 'requested'
            AND decided_by IS NULL AND decided_at_ms IS NULL AND consumed_at_ms IS NULL)
        OR (state IN ('approved', 'denied')
            AND decided_by IS NOT NULL AND decided_at_ms IS NOT NULL AND consumed_at_ms IS NULL)
        OR (state = 'consumed'
            AND decided_by IS NOT NULL AND decided_at_ms IS NOT NULL AND consumed_at_ms IS NOT NULL)
        OR (state = 'expired'
            AND consumed_at_ms IS NULL
            AND ((decided_by IS NULL AND decided_at_ms IS NULL)
                OR (decided_by IS NOT NULL AND decided_at_ms IS NOT NULL)))
    )
) STRICT, WITHOUT ROWID;

CREATE INDEX approvals_lookup ON approvals(caller_id, project_id, state, expires_at_ms);
