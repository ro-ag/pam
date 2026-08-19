CREATE TABLE capability_grants_v6 (
    grant_id TEXT PRIMARY KEY NOT NULL,
    caller_id TEXT NOT NULL REFERENCES callers(caller_id),
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    capability TEXT NOT NULL CHECK (length(capability) BETWEEN 1 AND 128),
    resource_kind TEXT NOT NULL CHECK (resource_kind IN ('any', 'exact')),
    resource TEXT CHECK (length(resource) BETWEEN 1 AND 1024),
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

INSERT INTO capability_grants_v6(
    grant_id, caller_id, project_id, capability, resource_kind, resource,
    effect, approval, expires_at_ms, revoked_at_ms, created_at_ms
)
SELECT
    grant_id, caller_id, project_id, capability, resource_kind, resource,
    effect, approval, expires_at_ms, revoked_at_ms, created_at_ms
FROM capability_grants;

DROP TABLE capability_grants;
ALTER TABLE capability_grants_v6 RENAME TO capability_grants;
CREATE INDEX capability_grants_lookup
    ON capability_grants(caller_id, project_id, capability, revoked_at_ms, expires_at_ms);

CREATE TABLE approvals_v6 (
    approval_id TEXT PRIMARY KEY NOT NULL,
    caller_id TEXT NOT NULL REFERENCES callers(caller_id),
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    capability TEXT NOT NULL CHECK (length(capability) BETWEEN 1 AND 128),
    resource TEXT NOT NULL CHECK (length(resource) BETWEEN 1 AND 1024),
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

INSERT INTO approvals_v6(
    approval_id, caller_id, project_id, capability, resource,
    effect_fingerprint, state, requested_at_ms, expires_at_ms,
    decided_by, decided_at_ms, consumed_at_ms
)
SELECT
    approval_id, caller_id, project_id, capability, resource,
    effect_fingerprint, state, requested_at_ms, expires_at_ms,
    decided_by, decided_at_ms, consumed_at_ms
FROM approvals;

DROP TABLE approvals;
ALTER TABLE approvals_v6 RENAME TO approvals;
CREATE INDEX approvals_lookup ON approvals(caller_id, project_id, state, expires_at_ms);
