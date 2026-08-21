CREATE TABLE skills_audit_reports (
    project_id TEXT PRIMARY KEY NOT NULL
        REFERENCES projects(project_id) ON DELETE CASCADE,
    observed_at_ms INTEGER NOT NULL CHECK (observed_at_ms >= 0),
    schema_version INTEGER NOT NULL
        CHECK (schema_version BETWEEN 1 AND 4294967295),
    report_json TEXT NOT NULL
        CHECK (
            length(CAST(report_json AS BLOB)) BETWEEN 2 AND 33554432
            AND CASE
                WHEN json_valid(report_json) THEN json_type(report_json) = 'object'
                ELSE 0
            END
        ),
    report_digest TEXT NOT NULL
        CHECK (
            length(report_digest) = 71
            AND substr(report_digest, 1, 7) = 'sha256:'
            AND substr(report_digest, 8) NOT GLOB '*[^0-9a-f]*'
        )
) STRICT, WITHOUT ROWID;
