CREATE TABLE callers (
    caller_id TEXT PRIMARY KEY NOT NULL
        CHECK (length(caller_id) BETWEEN 1 AND 256),
    credential_digest BLOB NOT NULL
        CHECK (length(credential_digest) = 32),
    registered_at_ms INTEGER NOT NULL CHECK (registered_at_ms >= 0),
    revoked_at_ms INTEGER CHECK (revoked_at_ms >= registered_at_ms)
) STRICT, WITHOUT ROWID;

CREATE INDEX callers_active ON callers(caller_id) WHERE revoked_at_ms IS NULL;
