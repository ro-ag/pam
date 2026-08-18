CREATE TABLE projects (
    project_id TEXT PRIMARY KEY NOT NULL,
    next_queue_sequence INTEGER NOT NULL DEFAULT 1
        CHECK (next_queue_sequence > 0)
) STRICT;

CREATE TABLE requests (
    request_id TEXT PRIMARY KEY NOT NULL,
    caller_id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    idempotency_key TEXT NOT NULL,
    operation_kind TEXT NOT NULL,
    operation BLOB NOT NULL,
    queue_sequence INTEGER NOT NULL CHECK (queue_sequence > 0),
    state TEXT NOT NULL
        CHECK (state IN (
            'queued', 'leased', 'cancellation_requested',
            'succeeded', 'failed', 'cancelled'
        )),
    accepted_at_ms INTEGER NOT NULL CHECK (accepted_at_ms >= 0),
    attempt INTEGER NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    lease_owner TEXT,
    lease_token TEXT,
    lease_expires_at_ms INTEGER CHECK (lease_expires_at_ms >= 0),
    completed_at_ms INTEGER CHECK (completed_at_ms >= 0),
    result BLOB,
    UNIQUE (caller_id, project_id, idempotency_key),
    UNIQUE (project_id, queue_sequence),
    CHECK (
        (state IN ('leased', 'cancellation_requested')
            AND lease_owner IS NOT NULL
            AND lease_token IS NOT NULL
            AND lease_expires_at_ms IS NOT NULL)
        OR
        (state NOT IN ('leased', 'cancellation_requested')
            AND lease_owner IS NULL
            AND lease_token IS NULL
            AND lease_expires_at_ms IS NULL)
    ),
    CHECK (
        (state IN ('succeeded', 'failed', 'cancelled')
            AND completed_at_ms IS NOT NULL
            AND result IS NOT NULL)
        OR
        (state = 'cancellation_requested'
            AND completed_at_ms IS NULL
            AND result IS NOT NULL)
        OR
        (state IN ('queued', 'leased')
            AND completed_at_ms IS NULL
            AND result IS NULL)
    )
) STRICT;

CREATE UNIQUE INDEX one_active_lease_per_project
    ON requests(project_id)
    WHERE state IN ('leased', 'cancellation_requested');

CREATE INDEX requests_claim_order
    ON requests(state, accepted_at_ms, project_id, queue_sequence);

CREATE INDEX requests_project_order
    ON requests(project_id, state, queue_sequence);

CREATE INDEX requests_expired_leases
    ON requests(state, lease_expires_at_ms)
    WHERE state IN ('leased', 'cancellation_requested');

CREATE TABLE events (
    request_id TEXT NOT NULL REFERENCES requests(request_id) ON DELETE CASCADE,
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    kind TEXT NOT NULL,
    payload BLOB NOT NULL,
    recorded_at_ms INTEGER NOT NULL CHECK (recorded_at_ms >= 0),
    PRIMARY KEY (request_id, sequence)
) STRICT, WITHOUT ROWID;
