CREATE TABLE evidence_blobs (
    digest TEXT PRIMARY KEY NOT NULL
        CHECK (
            length(digest) = 71
            AND substr(digest, 1, 7) = 'sha256:'
            AND substr(digest, 8) NOT GLOB '*[^0-9a-f]*'
        ),
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0)
) STRICT, WITHOUT ROWID;

CREATE TABLE evidence_handles (
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    handle TEXT NOT NULL
        CHECK (
            length(handle) BETWEEN 14 AND 512
            AND substr(handle, 1, 11) = 'evidence://'
        ),
    digest TEXT NOT NULL REFERENCES evidence_blobs(digest),
    media_type TEXT NOT NULL CHECK (length(media_type) BETWEEN 1 AND 255),
    retention TEXT NOT NULL
        CHECK (retention IN ('session', 'project', 'persistent')),
    redaction TEXT NOT NULL
        CHECK (redaction IN ('unredacted', 'redacted')),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    PRIMARY KEY (project_id, handle)
) STRICT, WITHOUT ROWID;

CREATE INDEX evidence_handles_digest ON evidence_handles(digest);
