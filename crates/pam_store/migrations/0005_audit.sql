CREATE TABLE audit_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT CHECK (sequence > 0),
    event_id TEXT NOT NULL UNIQUE
        CHECK (length(CAST(event_id AS BLOB)) BETWEEN 1 AND 256),
    project_id TEXT NOT NULL
        CHECK (length(CAST(project_id AS BLOB)) BETWEEN 1 AND 256),
    caller_id TEXT NOT NULL
        CHECK (length(CAST(caller_id AS BLOB)) BETWEEN 1 AND 256),
    action TEXT NOT NULL
        CHECK (length(CAST(action AS BLOB)) BETWEEN 1 AND 128),
    decision TEXT NOT NULL
        CHECK (length(CAST(decision AS BLOB)) BETWEEN 1 AND 64),
    outcome TEXT NOT NULL
        CHECK (length(CAST(outcome AS BLOB)) BETWEEN 1 AND 64),
    redacted_detail TEXT NOT NULL
        CHECK (length(CAST(redacted_detail AS BLOB)) <= 16384),
    occurred_at_ms INTEGER NOT NULL CHECK (occurred_at_ms >= 0),
    retain_until_ms INTEGER NOT NULL CHECK (retain_until_ms >= occurred_at_ms)
) STRICT;

CREATE INDEX audit_events_project_sequence
    ON audit_events(project_id, sequence);

CREATE INDEX audit_events_project_retention
    ON audit_events(project_id, retain_until_ms, sequence);

CREATE TABLE evidence_install_intents (
    attempt_id TEXT PRIMARY KEY
        CHECK (
            length(attempt_id) = 36
            AND attempt_id NOT GLOB '*[^0-9a-f-]*'
        ),
    digest TEXT NOT NULL
        CHECK (
            length(digest) = 71
            AND substr(digest, 1, 7) = 'sha256:'
            AND substr(digest, 8) NOT GLOB '*[^0-9a-f]*'
        ),
    temporary_name TEXT NOT NULL UNIQUE
        CHECK (
            length(temporary_name) = 36
            AND temporary_name NOT GLOB '*[^0-9a-f-]*'
        ),
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    started_at_ms INTEGER NOT NULL CHECK (started_at_ms >= 0)
) STRICT;

CREATE INDEX evidence_install_intents_stale
    ON evidence_install_intents(started_at_ms, attempt_id);

CREATE INDEX evidence_install_intents_digest
    ON evidence_install_intents(digest, started_at_ms);

CREATE TABLE evidence_gc_attempts (
    digest TEXT PRIMARY KEY,
    last_attempt_ms INTEGER NOT NULL CHECK (last_attempt_ms >= 0)
) STRICT;
