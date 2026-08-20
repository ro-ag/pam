CREATE TABLE flow_runs (
    request_id TEXT PRIMARY KEY NOT NULL
        REFERENCES requests(request_id) ON DELETE CASCADE,
    definition_digest BLOB NOT NULL CHECK(length(definition_digest) = 32),
    snapshot BLOB NOT NULL CHECK(length(snapshot) BETWEEN 1 AND 4194304),
    checkpoint_revision INTEGER NOT NULL CHECK(checkpoint_revision > 0),
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
    terminal_outcome TEXT CHECK(
        terminal_outcome IS NULL OR
        terminal_outcome IN ('solved', 'unresolved', 'blocked', 'cancelled')
    ),
    terminal_result BLOB CHECK(
        terminal_result IS NULL OR length(terminal_result) BETWEEN 1 AND 1048576
    ),
    terminal_cancellation_override INTEGER NOT NULL DEFAULT 0 CHECK(
        terminal_cancellation_override IN (0, 1)
    ),
    CHECK((terminal_outcome IS NULL) = (terminal_result IS NULL)),
    CHECK(terminal_cancellation_override = 0 OR terminal_outcome = 'blocked')
) STRICT, WITHOUT ROWID;
