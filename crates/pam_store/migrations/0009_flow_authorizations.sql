ALTER TABLE approvals ADD COLUMN flow_request_id TEXT
    CHECK(flow_request_id IS NULL OR length(flow_request_id) BETWEEN 1 AND 256);

CREATE TABLE flow_authorizations (
    request_id TEXT PRIMARY KEY NOT NULL
        REFERENCES requests(request_id) ON DELETE CASCADE,
    capability TEXT NOT NULL CHECK(length(capability) BETWEEN 1 AND 128),
    resource TEXT NOT NULL CHECK(length(resource) BETWEEN 1 AND 1024),
    effect_fingerprint BLOB NOT NULL CHECK(length(effect_fingerprint) = 32),
    authorization_kind TEXT NOT NULL
        CHECK(authorization_kind IN ('unconditional', 'approved')),
    approval_id TEXT UNIQUE REFERENCES approvals(approval_id),
    schema_approval_required INTEGER NOT NULL CHECK(schema_approval_required IN (0, 1)),
    authorized_at_ms INTEGER NOT NULL CHECK(authorized_at_ms >= 0),
    CHECK(
        (authorization_kind = 'unconditional' AND approval_id IS NULL)
        OR (authorization_kind = 'approved' AND approval_id IS NOT NULL)
    ),
    CHECK(schema_approval_required = 0 OR authorization_kind = 'approved')
) STRICT, WITHOUT ROWID;
